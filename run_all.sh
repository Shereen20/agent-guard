#!/usr/bin/env bash
# Full pipeline on a Colab/Kaggle T4. From repo root:  bash run_all.sh
set -e
pip install -q -r requirements.txt
cd src
python build_train.py && python build_redteam.py && python dedupe_check.py
# optional: python llm_expand.py --model <free-openrouter-model> && python dedupe_check.py
# BEFORE training (zero-shot)
python baselines.py --kind judge --model Qwen/Qwen2.5-0.5B-Instruct --name zs_qwen05b
python baselines.py --kind clf   --model protectai/deberta-v3-base-prompt-injection-v2 --name zs_protectai
# classical control
python tfidf_baseline.py && python tfidf_baseline.py --normalize
# AFTER training
python train.py --model answerdotai/ModernBERT-base --name modernbert
python train.py --model answerdotai/ModernBERT-base --name modernbert_norm --normalize
python train.py --model Qwen/Qwen2.5-0.5B --name qwen05b_lora --lora
for s in zs_qwen05b zs_protectai tfidf tfidf_norm modernbert modernbert_norm qwen05b_lora; do python eval.py --scores ../results/scores_$s.jsonl; done
python make_table.py
# Leave-one-technique-out adversarial fine-tune (generalisation to unseen bypass techniques):
# for T in b64_pipe zero_width nonenglish_injection indirect_makefile; do
#   AUG=$(python -c "import json;print(','.join(sorted({json.loads(l)['technique'] for l in open('../data/processed/redteam.jsonl')}-{'$T'})))")
#   python train.py --model answerdotai/ModernBERT-base --name loto_$T --aug_techniques $AUG
# done   (then read technique $T row in results/metrics_loto_$T.json -> by_technique)
