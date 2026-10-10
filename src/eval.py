"""Metrics from score files. Usage: python eval.py --scores results/scores_<name>.jsonl [--thresh t]
score file rows: {id, split, score}  (score = P(malicious)). Threshold is chosen on VAL (max-F1) unless
--thresh given, then applied unchanged to test/redteam: no tuning on the red-team set.
Reports: P/R/F1/FPR, PR-AUC, ROC-AUC, TPR@1%FPR, plus per-category / per-technique / hard-negative FPR."""
import argparse, json, numpy as np
from sklearn.metrics import precision_recall_fscore_support, average_precision_score, roc_auc_score, roc_curve, precision_recall_curve
from common import *

def tpr_at_fpr(y, s, target=0.01):
    if len(set(y)) < 2: return float("nan")
    fpr, tpr, _ = roc_curve(y, s); return float(tpr[fpr <= target].max()) if (fpr <= target).any() else 0.0

def metrics(y, s, t):
    y, s = np.array(y), np.array(s); p = (s >= t).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, p, average="binary", zero_division=0)
    fp = int(((p == 1) & (y == 0)).sum()); tn = int(((p == 0) & (y == 0)).sum())
    out = dict(n=len(y), pos=int(y.sum()), precision=pr, recall=rc, f1=f1, fpr=fp / max(fp + tn, 1))
    if len(set(y)) == 2:
        out.update(pr_auc=float(average_precision_score(y, s)), roc_auc=float(roc_auc_score(y, s)), tpr_at_1pct_fpr=tpr_at_fpr(y, s))
    return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in out.items()}

def best_thresh(y, s):
    pr, rc, th = precision_recall_curve(y, s); f = 2 * pr * rc / np.maximum(pr + rc, 1e-9)
    return float(th[np.argmax(f[:-1])])

def load(split, scores):
    rows = read_jsonl(f"../data/processed/{split}.jsonl"); sc = {r["id"]: r["score"] for r in scores if r["split"] == split and not (split == "redteam" and r.get("seen"))}
    return [r for r in rows if r["id"] in sc], [sc[r["id"]] for r in rows if r["id"] in sc]

def run(scores, thresh=None):
    res = {}
    vr, vs = load("val", scores)
    t = thresh if thresh is not None else (best_thresh([r["label"] for r in vr], vs) if vr else 0.5)
    res["threshold"] = round(t, 4)
    for split in ("train", "val", "test", "redteam"):
        rows, s = load(split, scores)
        if not rows: continue
        res[split] = metrics([r["label"] for r in rows], s, t)
        for key in ("surface", "category", "technique", "source"):
            grp = {}
            for r, x in zip(rows, s): grp.setdefault(r[key], []).append((r["label"], x))
            res[f"{split}_by_{key}"] = {k: dict(n=len(v), recall_on_malicious=round(float(np.mean([x >= t for l, x in v if l == 1])), 3) if any(l for l, _ in v) else None,
                                                 fpr_on_benign=round(float(np.mean([x >= t for l, x in v if l == 0])), 3) if any(1 - l for l, _ in v) else None)
                                         for k, v in sorted(grp.items())}
        hard = [(r["label"], x) for r, x in zip(rows, s) if r["category"] == "benign_hard"]
        if hard: res[f"{split}_hardneg_fpr"] = round(float(np.mean([x >= t for _, x in hard])), 4)
    return res

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--scores", required=True); ap.add_argument("--thresh", type=float)
    a = ap.parse_args(); r = run(read_jsonl(a.scores), a.thresh)
    out = a.scores.replace("scores_", "metrics_").replace(".jsonl", ".json"); json.dump(r, open(out, "w"), indent=1)
    for k in ("threshold", "train", "val", "test", "redteam"): print(k, r.get(k))
    print("hardneg FPR:", {s: r.get(f"{s}_hardneg_fpr") for s in ("test", "redteam")}); print("->", out)
