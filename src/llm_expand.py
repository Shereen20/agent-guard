"""Optional: expand TRAIN rows (only) with a free-tier LLM via OpenRouter. Never touches val/test/redteam.
  export OPENROUTER_API_KEY=...   python llm_expand.py --model meta-llama/llama-3.3-70b-instruct:free --per_row 2 --max_rows 150
Free model availability changes: record the exact model string you used in the README (data card).
Output: data/processed/train_llm.jsonl (source=llm_expanded); train.py / dedupe_check.py pick it up automatically.
Prefer expanding your *authored seeds* and *hard negatives*; manually spot-check ~10% (label flips happen)."""
import argparse, os, json, re, requests, random, hashlib
from common import *
ap = argparse.ArgumentParser(); ap.add_argument("--model", required=True)
ap.add_argument("--per_row", type=int, default=2); ap.add_argument("--max_rows", type=int, default=150); a = ap.parse_args()
rows = [r for r in read_jsonl("../data/processed/train.jsonl")]
random.Random(0).shuffle(rows)
# prioritise authored seeds and hard negatives
rows.sort(key=lambda r: (r["source"] != "authored_seed", r["category"] != "benign_hard"))
SYS = ("You help build a labeled dataset to train a security classifier for coding agents. Given one example (serialized tool call or tool "
       "output) and its label, write {n} NEW variants that keep the SAME label and intent but change wording, tools, paths, hosts, formatting. "
       "Keep the '[TOOL_CALL] tool: args' / '[TOOL_OUTPUT] tool: content' prefix format. Use only reserved/example domains and IPs. "
       "Return a JSON list of strings only.")
out, seen = [], set()
for r in rows[: a.max_rows]:
    try:
        resp = requests.post("https://openrouter.ai/api/v1/chat/completions", timeout=90,
            headers={"Authorization": f"Bearer {os.environ['OPENROUTER_API_KEY']}"},
            json={"model": a.model, "messages": [{"role": "system", "content": SYS.format(n=a.per_row)},
                  {"role": "user", "content": f"label={'MALICIOUS' if r['label'] else 'BENIGN'}\n{r['text']}"}]}).json()
        txt = resp["choices"][0]["message"]["content"]; xs = json.loads(re.search(r"\[.*\]", txt, re.S).group(0))
    except Exception as e:
        print("skip:", type(e).__name__); continue
    for x in xs:
        if isinstance(x, str) and x.startswith("[") and x not in seen:
            seen.add(x); out.append(dict(id=hashlib.md5(x.encode()).hexdigest()[:10], text=x, label=r["label"], surface=r["surface"],
                category=r["category"], family=r["family"], technique=r["technique"], source="llm_expanded", split="train", llm=a.model))
write_jsonl("../data/processed/train_llm.jsonl", out); print(len(out), "rows written")
