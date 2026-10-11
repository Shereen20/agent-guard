# agent-guard: a guardrail for coding-agent tool calls and tool outputs

Repello AI Research Engineer assignment, **Track 1 (agentic tool-call guardrail)**.

A coding agent (Claude Code, Cursor, ...) runs shell commands and reads files, web pages and API responses with little supervision.
This repo builds and stress-tests a detector for two attack surfaces:

1. **Malicious tool calls**: destructive actions, credential exfiltration, CI / supply-chain tampering, persistence, argument poisoning, and multi-step "write a script, then run it" laundering.
2. **Tool-output prompt injection**: hidden instructions inside files, web pages, API JSON, issues/PRs, logs and MCP tool descriptions.

The work follows the attack -> defense -> measurement loop: build data, measure zero-shot baselines ("before"), fine-tune ("after"), attack the detector with a separate red-team set, and measure again.

## Status (read first)

| Part | State |
|---|---|
| Data pipeline, red-team set, leakage check, eval harness | Done and verified on CPU |
| Classical TF-IDF control | Done (numbers below) |
| Zero-shot baselines, fine-tuned detectors, leave-one-technique-out | **Scripts written, not yet run.** Run `notebooks/agent_guard_colab.ipynb` on a Colab T4; results land in `results/` and `results/RESULTS.md` |
| Authored seeds (`data/seeds/mine*.jsonl`) | **Not yet written.** Only AI-drafted rows exist and they are tagged `llm_draft` |
| Public Hugging Face artifacts | Not yet uploaded (last notebook cell does it) |
| Write-up | `REPORT.md`, to be filled from real results |

No transformer result appears in this README because none has been produced yet. Do not read the TF-IDF numbers below as the detector's performance.

## Repository layout
```
src/common.py          schema, text serialization, normalize() (NFKC, zero-width strip, base64/hex decode)
src/build_train.py     train/val/test from template families + seed files; test = held-out families
src/build_redteam.py   red-team set: 299 rows, 16 bypass techniques, benign twins for every technique
src/dedupe_check.py    exact / family / technique / char-5-gram cosine overlap vs train; exits non-zero on overlap
src/llm_expand.py      optional expansion of TRAIN rows with a free-tier OpenRouter model
src/baselines.py       zero-shot "before": small-LM judge, ProtectAI DeBERTa, Llama Prompt Guard 2
src/tfidf_baseline.py  char n-gram logistic regression (the "is it just keywords?" control)
src/train.py           ModernBERT / DeBERTa full fine-tune, or Qwen2.5 + LoRA; class-weighted loss
src/eval.py            F1, PR-AUC, ROC-AUC, TPR@1%FPR, per surface / category / technique / source
src/make_table.py      collects metrics into results/RESULTS.md
notebooks/agent_guard_colab.ipynb   runs everything on a free Colab T4
run_all.sh             same pipeline as a shell script
data/seeds/            seed examples (see data/seeds/README.md for the provenance rule)
data/processed/        generated train / val / test / redteam jsonl
```

## How to run
Easiest: open `notebooks/agent_guard_colab.ipynb` in Colab, choose a T4 GPU, upload a zip of this repo, run the cells top to bottom, and download `results.zip`.

From a shell on a GPU machine:
```
pip install -r requirements.txt
bash run_all.sh
```
CPU-only check of the data pipeline and control baseline (no GPU, no downloads):
```
pip install scikit-learn numpy
cd src
python build_train.py && python build_redteam.py && python dedupe_check.py
python tfidf_baseline.py && python eval.py --scores ../results/scores_tfidf.jsonl
```
Optional: `export OPENROUTER_API_KEY=...` and run `python llm_expand.py --model <free model>` to expand training rows. Record the exact model string in the data card below.

## Data

Each example is one JSON line: `text, label (1 = malicious), surface, category, family, technique, source, split`.
The `text` is a serialized tool call (`[TOOL_CALL] bash: ...`, optionally preceded by `[CONTEXT] ...` earlier turns) or tool output (`[TOOL_OUTPUT] read_file: ...`), identical in format for train and red-team so formatting cannot be the signal.

**Design decisions**
- **Splits are by attack family, not random.** Rows inside a template family are near-duplicates; a random split would leak them and inflate scores. Test families are held out entirely (`arg_poison_basic`, `inj_issue_text`, `benign_git`, `benign_json`, half of `hardneg_outputs`, plus every seed family ending in `_ho`). Validation is a stratified random 15% of the remaining rows, used only for model and threshold selection.
- **Hard negatives are first-class.** Scary-looking but legitimate commands (`rm -rf node_modules`, `git push --force-with-lease`, `curl` to PyPI) and documents that merely discuss injection are included in every split, because a detector that flags normal developer work gets switched off.
- **The red-team set is disjoint from training** in families, techniques, hosts, file paths and wording, and `dedupe_check.py` enforces it. Techniques: base64 / hex pipes, env-variable and quote splitting, Cyrillic homoglyphs, zero-width characters, Makefile / git-hook / Python-script indirection, payloads split across turns, non-English injection, markdown alt-text injection, poisoned MCP tool descriptions, polite injections with no trigger words, and benign-looking flags. **Every technique has benign twins** (legitimate `base64 -d`, Russian and Hindi docs, husky hooks, ...), otherwise "flag anything encoded" would score perfectly.
- **The decision threshold is picked on validation and then frozen.** It is never tuned on test or red-team. The headline robustness metric is TPR at 1% FPR, because validation thresholds do not transfer under distribution shift (visible in the control results below).
- Red-team rows used for adversarial fine-tuning are marked `seen` and excluded from red-team metrics. Generalisation to unseen techniques is measured with leave-one-technique-out runs.

**Data card**

| Item | Value |
|---|---|
| Train / val / test / red-team rows | 350 / 60 / 132 / 299 |
| Provenance (train+val+test) | 417 `template` (slot-filled from hand-written templates in `build_train.py`), 125 `llm_draft`, 0 `authored_seed` so far |
| `llm_draft` rows | drafted with Claude (Anthropic) in a chat session, not via an API; reviewed by the author: ___ (fill in) |
| `authored_seed` rows | ___ written or adapted by the author from their own shell history and reading (fill in once `data/seeds/mine.jsonl` exists) |
| `llm_expanded` rows | 0 so far; if `llm_expand.py` is used, free-tier model: ___ |
| Class balance (train) | about 65% malicious; handled with class-weighted loss |

Known weakness: the template and draft rows share a small set of authors and phrasing habits, so scores on them are optimistic. The authored-only slice (`source = authored_seed`) is reported separately by `eval.py` for exactly this reason.

## Method

**Detector choice.** Two candidates are trained and compared, plus a zero-shot judge as the "before" reference:
- *Small encoder* (ModernBERT-base, DeBERTa-v3-base): cheap and fast on the hot path of every tool call; ModernBERT's 8k context helps with long tool outputs.
- *Small decoder with a classification head* (Qwen2.5-0.5B + LoRA): better at shell semantics and partial obfuscation, at higher latency.
- Latency and parameter count are recorded per model (`results/latency_*.json`) so cost sits next to accuracy.
- Long inputs use head-plus-tail truncation, since injections often sit at the end of tool outputs.

**Before / after.** "Before" = zero-shot Qwen2.5 0.5B/1.5B as a YES/NO judge (score = P(YES) at the first token), ProtectAI's deberta-v3 prompt-injection classifier, and Llama Prompt Guard 2. The injection-only classifiers are not built for shell commands, so low recall on tool calls is a scope mismatch, not a model failure. "After" = the fine-tuned detectors on train, val, test and red-team.

**Controls to run before trusting any number**: shuffled-label training (should drop to chance), prefix-stripped text, authored-only slice, bootstrap confidence intervals (val and test are small), and false alerts per 1,000 benign tool calls on real shell history.

## Results so far (CPU control only, not the detector)

TF-IDF character n-gram logistic regression, threshold chosen on validation, 542 labeled rows:

| split | F1 | FPR | PR-AUC | TPR@1%FPR |
|---|---|---|---|---|
| val (in-family) | 0.925 | 0.190 | 0.980 | 0.769 |
| test (held-out families) | 0.814 | 0.518 | 0.946 | 0.750 |
| red-team | 0.903 | 0.082 | 0.987 | 0.767 |
| red-team, with `normalize()` | 0.958 | 0.082 | 0.995 | 0.910 |

Last digits can differ by about 0.003 between machines. Observations: (1) ranking quality (PR-AUC) holds up under shift but the validation threshold does not, so FPR jumps on the held-out test families; (2) input normalization (decoding base64 / hex, stripping zero-width characters) lifts red-team TPR@1%FPR from 0.77 to 0.91 for this baseline, so part of the red-team difficulty is fixable by preprocessing rather than learning; (3) a shuffled-label control gave chance-level scores and stripping the `[TOOL_CALL]` prefixes barely moved results, so the harness is not leaking labels through formatting. Transformer results will be added to `results/RESULTS.md` after the Colab run.

## What is reused versus written

| Source | Taken from it | Written here |
|---|---|---|
| AgentDojo (Debenedetti et al., 2024, arXiv:2406.13352) | threat-model framing of tool-output injection against agents | all data, no AgentDojo tasks or text copied |
| InjecAgent (Zhan et al., 2024, arXiv:2403.02691) | attack categories for indirect injection in tool responses | all data written from scratch |
| Agent Security Bench (Zhang et al., 2024, arXiv:2410.02644) | breadth of attack surfaces (tool descriptions, memory, observation) used to pick red-team techniques | all data written from scratch |
| Greshake et al., 2023, arXiv:2302.12173 | indirect prompt-injection concept | n/a |
| ModernBERT (Warner et al., 2024, arXiv:2412.13663) | model weights and architecture via `transformers` | fine-tuning loop, loss, truncation |
| DeBERTa-v3 (He et al., 2021, arXiv:2111.09543) | model weights via `transformers` | same as above |
| Qwen2.5 (Qwen Team, 2024, arXiv:2412.15115) | model weights via `transformers` | LoRA classification setup, zero-shot judge prompt |
| LoRA (Hu et al., 2021, arXiv:2106.09685) and PEFT library | adapter implementation | which layers and rank to use |
| Llama Prompt Guard 2 (Meta) and `protectai/deberta-v3-base-prompt-injection-v2` | used unmodified as zero-shot baselines | evaluation on this repo's splits |
| Hugging Face `transformers`, `peft`, scikit-learn | training and evaluation primitives | everything in `src/` |

No public dataset is included in or copied into the training or test data. Corrections welcome if any citation detail above is wrong; verify each against the paper before submitting.

## AI assistance disclosure
The initial scaffold of this repository (scripts, templates, the 125 `llm_draft` rows, the Colab notebook) was written with Claude (Anthropic) through a chat interface. The author is responsible for reviewing, running and explaining all of it. Rows that the author writes or genuinely adapts live in `data/seeds/mine*.jsonl` and are the only rows tagged `authored_seed`.

## Known limitations
- The training set is small (350 rows) and thin on benign tool outputs; validation and test are small enough that differences of a few rows are noise.
- The attack taxonomy and the red-team set were written by one author before any detector existed, so they miss attacks that author did not think of. An adaptive second round against the trained model, ideally by a different person, is needed.
- Single-turn and two-turn contexts only; long multi-turn laundering is not covered.
- Detection happens on text; it does not check what a command actually does on a live system.
