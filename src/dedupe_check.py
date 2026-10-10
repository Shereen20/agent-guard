"""Proves red-team set doesn't overlap train: exact match, family/technique overlap, and
nearest-neighbour char 5-gram TF-IDF cosine. Writes results/dedupe.json; exits 1 if any red-team row
is an exact dup or has cosine >= --thresh to any train/val/test row."""
import argparse, json, sys
from sklearn.feature_extraction.text import TfidfVectorizer
from common import *
ap = argparse.ArgumentParser(); ap.add_argument("--thresh", type=float, default=0.85); a = ap.parse_args()
tr = sum([read_jsonl(f"../data/processed/{s}.jsonl") for s in ("train", "val", "test")], [])
import os
if os.path.exists("../data/processed/train_llm.jsonl"): tr += read_jsonl("../data/processed/train_llm.jsonl")
rt = read_jsonl("../data/processed/redteam.jsonl")
v = TfidfVectorizer(analyzer="char", ngram_range=(5, 5), min_df=1).fit([r["text"] for r in tr + rt])
S = (v.transform([r["text"] for r in rt]) @ v.transform([r["text"] for r in tr]).T).toarray()
mx = S.max(1); exact = len({r["text"] for r in rt} & {r["text"] for r in tr})
fam_overlap = sorted({r["family"] for r in rt} & {r["family"] for r in tr})
tech_overlap = sorted({r["technique"] for r in rt} & {r["technique"] for r in tr} - {"none"})
res = dict(n_redteam=len(rt), exact_dups=exact, max_cosine=float(mx.max()), mean_max_cosine=float(mx.mean()),
           n_above_thresh=int((mx >= a.thresh).sum()), family_overlap=fam_overlap, technique_overlap=tech_overlap)
print(json.dumps(res, indent=1)); json.dump(res, open("../results/dedupe.json", "w"), indent=1)
sys.exit(1 if exact or (mx >= a.thresh).any() or fam_overlap else 0)
