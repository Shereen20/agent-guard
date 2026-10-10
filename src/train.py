"""Fine-tune a sequence classifier (encoder full-FT, or decoder + LoRA) on data/processed/train.jsonl.

  python train.py --model answerdotai/ModernBERT-base --name modernbert
  python train.py --model microsoft/deberta-v3-base   --name deberta
  python train.py --model Qwen/Qwen2.5-0.5B           --name qwen05b_lora --lora
  python train.py ... --normalize                      # NFKC + zero-width strip + b64/hex decode (ablation)
  python train.py ... --aug_techniques b64_pipe,hex_printf   # adversarial fine-tune with some red-team techniques;
                                                       # those rows are flagged `seen` and excluded from red-team metrics
Writes ../results/scores_<name>.jsonl, ../results/latency_<name>.json, ../artifacts/<name>/.
"""
import argparse, json, os, time, numpy as np, torch
from torch import nn
from transformers import (AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer, set_seed)
from sklearn.metrics import f1_score
from common import *

ap = argparse.ArgumentParser()
ap.add_argument("--model", required=True); ap.add_argument("--name", required=True)
ap.add_argument("--lora", action="store_true"); ap.add_argument("--epochs", type=float, default=4)
ap.add_argument("--lr", type=float); ap.add_argument("--bs", type=int, default=16)
ap.add_argument("--max_len", type=int, default=512); ap.add_argument("--seed", type=int, default=0)
ap.add_argument("--normalize", action="store_true"); ap.add_argument("--aug_techniques", default="")
a = ap.parse_args(); set_seed(a.seed)
lr = a.lr or (1e-4 if a.lora else 3e-5)
prep = normalize if a.normalize else (lambda t: t)

tok = AutoTokenizer.from_pretrained(a.model)
if tok.pad_token is None: tok.pad_token = tok.eos_token

def encode(text):
    """Head+tail truncation: injections often sit at the END of long tool outputs."""
    ids = tok(prep(text), add_special_tokens=True, truncation=False)["input_ids"]
    if len(ids) > a.max_len:
        h = a.max_len // 2; ids = ids[:h] + ids[-(a.max_len - h):]
    return ids

class DS(torch.utils.data.Dataset):
    def __init__(s, rows): s.rows = rows; s.ids = [encode(r["text"]) for r in rows]
    def __len__(s): return len(s.rows)
    def __getitem__(s, i): return dict(input_ids=s.ids[i], labels=s.rows[i]["label"])

def collate(b):
    m = max(len(x["input_ids"]) for x in b); pid = tok.pad_token_id
    ids = torch.tensor([x["input_ids"] + [pid] * (m - len(x["input_ids"])) for x in b])
    att = torch.tensor([[1] * len(x["input_ids"]) + [0] * (m - len(x["input_ids"])) for x in b])
    return dict(input_ids=ids, attention_mask=att, labels=torch.tensor([x["labels"] for x in b]))

D = lambda s: read_jsonl(f"../data/processed/{s}.jsonl") + (read_jsonl("../data/processed/train_llm.jsonl") if s == "train" and os.path.exists("../data/processed/train_llm.jsonl") else [])
train, val, test, rt = D("train"), D("val"), D("test"), D("redteam")
aug = {t for t in a.aug_techniques.split(",") if t}
seen_ids = {r["id"] for r in rt if r["technique"] in aug}
train = train + [r for r in rt if r["id"] in seen_ids]
print(f"train={len(train)} (aug rows={len(seen_ids)}) val={len(val)} test={len(test)} redteam={len(rt)}")

model = AutoModelForSequenceClassification.from_pretrained(a.model, num_labels=2)
model.config.pad_token_id = tok.pad_token_id
if a.lora:
    from peft import LoraConfig, get_peft_model
    model = get_peft_model(model, LoraConfig(task_type="SEQ_CLS", r=16, lora_alpha=32, lora_dropout=0.05, target_modules="all-linear"))
    model.print_trainable_parameters()

pos = sum(r["label"] for r in train); w = torch.tensor([len(train) / (2 * (len(train) - pos)), len(train) / (2 * pos)], dtype=torch.float)

class WTrainer(Trainer):   # class-weighted CE: train set is malicious-heavy
    def compute_loss(self, model, inputs, return_outputs=False, **kw):
        y = inputs.pop("labels"); out = model(**inputs)
        loss = nn.functional.cross_entropy(out.logits.float(), y, weight=w.to(out.logits.device))
        return (loss, out) if return_outputs else loss

def cm(p): return dict(f1=f1_score(p.label_ids, p.predictions.argmax(-1)))
args = TrainingArguments(output_dir=f"../artifacts/{a.name}_ckpt", per_device_train_batch_size=a.bs, per_device_eval_batch_size=32,
    num_train_epochs=a.epochs, learning_rate=lr, weight_decay=0.01, warmup_ratio=0.1, eval_strategy="epoch", save_strategy="epoch",
    load_best_model_at_end=True, metric_for_best_model="f1", save_total_limit=1, fp16=torch.cuda.is_available(),
    logging_steps=10, report_to="none", seed=a.seed, remove_unused_columns=False)
tr = WTrainer(model=model, args=args, train_dataset=DS(train), eval_dataset=DS(val), data_collator=collate, compute_metrics=cm)
tr.train()
os.makedirs(f"../artifacts/{a.name}", exist_ok=True); tr.save_model(f"../artifacts/{a.name}"); tok.save_pretrained(f"../artifacts/{a.name}")

# ---- scores for every split (+ `seen` flag for red-team rows that were trained on)
out = []
for name, rows in (("train", train[:len(train) - len(seen_ids)] if seen_ids else train), ("val", val), ("test", test), ("redteam", rt)):
    lg = tr.predict(DS(rows)).predictions; p = torch.softmax(torch.tensor(lg).float(), -1)[:, 1].numpy()
    out += [dict(id=r["id"], split=name, score=float(x), seen=(r["id"] in seen_ids)) for r, x in zip(rows, p)]
write_jsonl(f"../results/scores_{a.name}.jsonl", out)

# ---- latency (single example, the guardrail's hot-path case)
model.eval(); dev = next(model.parameters()).device; ex = DS(test[:50]); ts = []
with torch.no_grad():
    for i in range(len(ex)):
        b = collate([ex[i]]); b.pop("labels"); b = {k: v.to(dev) for k, v in b.items()}
        if dev.type == "cuda": torch.cuda.synchronize()
        t0 = time.perf_counter(); model(**b)
        if dev.type == "cuda": torch.cuda.synchronize()
        ts.append((time.perf_counter() - t0) * 1000)
json.dump(dict(device=str(dev), p50_ms=float(np.median(ts[5:])), p95_ms=float(np.percentile(ts[5:], 95)),
               params_m=sum(p.numel() for p in model.parameters()) / 1e6), open(f"../results/latency_{a.name}.json", "w"))
print("done ->", f"../results/scores_{a.name}.jsonl")
