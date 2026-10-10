"""Collect results/metrics_*.json into results/RESULTS.md (the table for the report)."""
import glob, json, os
rows = []
for p in sorted(glob.glob("../results/metrics_*.json")):
    m = json.load(open(p)); n = os.path.basename(p)[8:-5]
    lat = f"../results/latency_{n}.json"; l = json.load(open(lat)) if os.path.exists(lat) else {}
    g = lambda s, k: m.get(s, {}).get(k, "-")
    rows.append(f"| {n} | {g('val','f1')} | {g('test','f1')} | {g('test','tpr_at_1pct_fpr')} | {g('redteam','f1')} | {g('redteam','pr_auc')} | "
                f"{g('redteam','tpr_at_1pct_fpr')} | {m.get('redteam_hardneg_fpr','-')} | {l.get('p50_ms','-') if not l else round(l['p50_ms'],1)} |")
hdr = "| model | val F1 | test F1 (held-out families) | test TPR@1%FPR | red-team F1 | red-team PR-AUC | red-team TPR@1%FPR | red-team hard-neg FPR | p50 ms |\n|---|---|---|---|---|---|---|---|---|\n"
open("../results/RESULTS.md", "w").write(hdr + "\n".join(rows) + "\n"); print(hdr + "\n".join(rows))
