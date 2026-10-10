"""Classical baseline: char n-gram TF-IDF + logistic regression. Not a serious detector; it's the
'is it just keywords/style?' control. If a transformer barely beats this on the red-team set, it learned keywords."""
import sys
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from common import *
norm = len(sys.argv) > 1 and sys.argv[1] == "--normalize"
f = (lambda t: normalize(t)) if norm else (lambda t: t)
tr = read_jsonl("../data/processed/train.jsonl")
v = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True)
m = LogisticRegression(max_iter=2000, class_weight="balanced").fit(v.fit_transform([f(r["text"]) for r in tr]), [r["label"] for r in tr])
out = []
for s in ("train", "val", "test", "redteam"):
    rows = read_jsonl(f"../data/processed/{s}.jsonl")
    p = m.predict_proba(v.transform([f(r["text"]) for r in rows]))[:, 1]
    out += [dict(id=r["id"], split=s, score=float(x)) for r, x in zip(rows, p)]
write_jsonl(f"../results/scores_tfidf{'_norm' if norm else ''}.jsonl", out)
