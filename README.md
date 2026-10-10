# agent-guard: tool-call + tool-output guardrail for coding agents (Repello AI, Track 1)

Detector for two attack surfaces: (1) malicious / dangerous **tool calls** (destructive, exfiltration, CI/supply-chain tampering,
persistence, argument poisoning, multi-step laundering) and (2) **tool-output prompt injection** (files, web pages, API JSON, issues, MCP tool descriptions).
Loop: build dataset -> zero-shot "before" -> fine-tune "after" -> red-team on a disjoint set -> measure.

## Layout
```
src/common.py          schema, serialization, normalize() (NFKC + zero-width strip + b64/hex decode)
src/build_train.py     train/val/test (template families + YOUR authored seeds); test = held-out FAMILIES
src/llm_expand.py      optional free-tier OpenRouter expansion of TRAIN rows only
src/build_redteam.py   red-team set: disjoint families, techniques, hosts, paths; benign twins per technique
src/dedupe_check.py    exact / family / technique / char-5gram cosine overlap vs train (fails the run on overlap)
src/baselines.py       zero-shot "before": small-LM judge, ProtectAI DeBERTa, Llama Prompt Guard 2
src/tfidf_baseline.py  char n-gram LR control ("is it just keywords?")
src/train.py           ModernBERT/DeBERTa full FT or Qwen2.5 + LoRA seq-cls; class-weighted loss; head+tail truncation
src/eval.py            F1, PR-AUC, ROC-AUC, TPR@1%FPR, per surface/category/technique, hard-negative FPR
src/make_table.py      results/RESULTS.md
run_all.sh             whole pipeline for a Colab/Kaggle T4
```

## Run
```
git clone <repo> && cd agent-guard && bash run_all.sh      # Colab/Kaggle GPU runtime
```
Add your own examples first (`data/seeds/README.md`), and set `OPENROUTER_API_KEY` if you use `llm_expand.py`
(record the exact free model string in the data card below).

## Design decisions (short)
- **Splits by family, not random.** Templates within a family are near-duplicates; random splits inflate scores.
- **Threshold is picked on val and frozen**; never tuned on test/red-team. Headline robustness metric is TPR@1%FPR (threshold-free) because val thresholds do not transfer under shift (see sanity numbers).
- **Every red-team technique has benign twins** (legit `base64 -d`, Russian/Hindi docs, husky hooks...). Otherwise "flag anything encoded" scores perfectly.
- **Red-team rows used for adversarial fine-tuning are flagged `seen` and excluded from red-team metrics**; use leave-one-technique-out (bottom of `run_all.sh`).

## Status of this repo (read this)
- Verified in a CPU sandbox: data builders, dedupe check (0 exact dups, 0 family/technique overlap, max cosine 0.67), eval harness, TF-IDF baseline.
- **Not yet run:** `train.py` and `baselines.py` (need GPU + Hugging Face downloads). They compile; expect small first-run fixes.
- Template-generated train set is small (270 train rows) and **thin on benign tool outputs (12 in train)**. Grow it with your authored seeds + `llm_expand.py` before trusting numbers.
- No authored seeds ship with the repo, on purpose: the brief requires examples you wrote, and ones I wrote would misreport provenance.

### CPU sanity numbers (TF-IDF char n-gram LR, real run, threshold from val)
| split | F1 | FPR | PR-AUC | TPR@1%FPR |
|---|---|---|---|---|
| val (in-family) | 0.971 | 0.143 | 0.995 | 0.879 |
| test (held-out families) | 0.772 | 0.923 | 0.975 | 0.639 |
| red-team | 0.848 | 0.618 | 0.960 | 0.656 |
With `normalize()`: red-team PR-AUC 0.960 -> 0.983, TPR@1%FPR 0.656 -> 0.783. Ranking holds up under shift; the val threshold does not (FPR explodes).
These are a floor to beat, and a hint that the data is easy: expect the transformer gap to come from hard negatives and red-team techniques.

## Citations (fill in what you actually used)
AgentDojo (Debenedetti et al. 2024), InjecAgent (Zhan et al. 2024), Agent Security Bench (Zhang et al. 2024), Llama Prompt Guard 2 (Meta), ProtectAI deberta-v3-base-prompt-injection-v2, ModernBERT (Warner et al. 2024), DeBERTa-v3 (He et al. 2021), LoRA (Hu et al. 2021), Qwen2.5 (Qwen Team 2024). For each: one line on what you took vs. implemented.

## Data card (fill in)
free-tier models used for expansion: ___ ; authored seeds: ___ rows ; template rows: ___ ; llm_expanded rows: ___
