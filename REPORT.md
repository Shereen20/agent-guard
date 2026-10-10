# Report (4-5 pages): fill with YOUR results and reasoning; delete this line

1. **Problem and threat model.** What the guardrail sees (tool call / tool output / short context), where it sits, what it must not break (FPR on normal dev work).
2. **Data.** Sources and provenance counts (authored / template / LLM + model names); category table; hard negatives and why; family split rationale; what you checked for LLM-style leakage (authored-only eval).
3. **Detector choice.** ModernBERT/DeBERTa vs Qwen+LoRA vs small-LM judge: accuracy, latency (results/latency_*.json), cost, context length. What you rejected and why.
4. **Before/after.** Zero-shot baselines vs fine-tuned on train/val/test (table from results/RESULTS.md). Note scope mismatch for injection-only models.
5. **Red-team.** Each technique: what you tried, what worked, what failed, with example rows. Table by technique. Normalization ablation. Leave-one-technique-out result.
6. **Weaknesses / what broke / next steps.** Threshold shift, small data, thin benign outputs, multi-turn depth, adaptive attackers, what you would do with more compute.
