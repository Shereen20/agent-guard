# Your authored seeds go here

The brief requires examples that are **written or adapted by you** (not 100% LLM-generated / public datasets).
Put them in `data/seeds/*.jsonl`; `build_train.py` picks them up automatically and tags them `source=authored_seed`
(so the report can show results on authored-only rows - the check that "LLM style" isn't the signal).

One JSON per line (see `TEMPLATE.jsonl.example`). Aim for 100-200, spread over: destructive, exfiltration, ci_supply_chain,
persistence, arg_poisoning, injection (file / web / API / issue / MCP description), laundering (multi-step) AND hard negatives
(`category: benign_hard`) drawn from your real dev history (commands you actually run, docs you actually read).
Adapt, don't copy: take real incident write-ups / CVE PoCs / AgentDojo-style tasks and rewrite them in your own words.
Use a **new `family` name** per idea; the held-out test families are chosen by name in `build_train.py` (TEST_FAMILIES).

## Provenance rule (enforced by build_train.py)
- Files named `mine*.jsonl` are tagged `source=authored_seed`: only put rows there that you wrote or genuinely adapted.
- Any other file (e.g. `draft_claude.jsonl`, AI-drafted starter rows) is tagged `source=llm_draft`. To promote a draft row, edit it
  to reflect your own judgement/experience, then move it into `mine.jsonl`.
- Families ending in `_ho` are held out into the TEST split (family-level generalisation).
