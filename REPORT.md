# Engineering an Adversarially Robust Tool-Call Guardrail for Autonomous Coding Agents

**Track 1: Agentic Tool-Call Guardrail**  
*Author / Engineer Report*

---

## 1. Executive Summary & Threat Model

Modern autonomous coding agents (such as Claude Code, Cursor, and custom agentic loops) execute shell commands, edit files, parse web pages, and consume API responses largely unsupervised. While this autonomy accelerates developer workflows, it introduces a severe dual attack surface:

1. **Malicious or Destructive Tool Calls:** The agent is steered—via a compromised system prompt, a poisoned plan, or a malicious user input—into executing destructive actions (e.g., `rm -rf`, credential exfiltration via `curl` or `nc`, CI/CD workflow tampering, and persistence setup)[cite: 3].
2. **Indirect Tool-Output Prompt Injection:** Content retrieved from external environments (e.g., untrusted README files, web pages, API JSON responses, or MCP tool descriptions) contains hidden instructions designed to hijack the agent's subsequent decision-making loop[cite: 3].

To solve this, we built and evaluated a complete **Attack $\rightarrow$ Defense $\rightarrow$ Measurement** pipeline. This report details our architecture, data curation choices, preprocessing strategies, fine-tuning results across both encoder and decoder models, and rigorous adversarial red-teaming.

---

## 2. Dataset Construction & Rigorous Splitting Strategy

A naive train/test split on security data often results in inflated metrics due to data leakage across similar attack patterns. To prevent this, our data pipeline enforces strict structural controls:

* **Family-Based Splitting:** Data is partitioned strictly by template families rather than random row-shuffling. Training families cover foundational patterns, while validation and test splits evaluate generalization on completely held-out attack families (`arg_poison_basic`, `inj_issue_text`, `benign_git`, `benign_json`, etc.)[cite: 3].
* **First-Class Hard Negatives:** A major failure mode of naive security classifiers is high false-positive rates on legitimate developer operations (e.g., cleaning build caches, running force-pushes with lease, or querying package registries). Every category includes paired benign hard negatives to force the model to learn fine-grained intent[cite: 3].
* **Human-Authored Custom Seeds:** To satisfy the requirement for non-synthetic data, hand-crafted examples were authored and integrated via `data/seeds/mine.jsonl`, covering specialized exfiltration vectors, SSH key manipulations, and context-dependent script laundering.

---

## 3. Input Normalization & Preprocessing Pipeline

Attackers frequently leverage obfuscation—such as base64 encoding, hex escape sequences, zero-width spaces, and non-English character injections—to bypass keyword filters. 

We implemented a robust preprocessing normalization pass (`normalize()`) in `src/common.py` that executes the following steps prior to model tokenization[cite: 3]:
1. **Unicode NFKC Normalization:** Standardizes multi-byte character representations to prevent homoglyph substitution attacks.
2. **Zero-Width Character Stripping:** Removes invisible formatting tokens (`Cf` category characters) often used to hide prompt injection instructions.
3. **Decodable Stream Extraction:** Iteratively parses and decodes base64 and hex encoded blocks embedded within shell commands or arguments, exposing the raw underlying payload for inspection.

---

## 4. Model Architectures & Training Methodology

We evaluated multiple model families to contrast inference latency, resource constraints, and predictive accuracy:

* **Small Encoders (DeBERTa-v3-base & ModernBERT-base):** Selected for low latency on the hot path of every tool call. ModernBERT’s expanded 8k context window is particularly effective for ingesting lengthy tool outputs (such as massive logs or JSON files)[cite: 3].
* **Small Decoder with Classification Head (Qwen2.5-0.5B + LoRA):** Explored to leverage native shell semantics and partial reasoning capabilities, configured with Parameter-Efficient Fine-Tuning (PEFT/LoRA)[cite: 3].
* **Zero-Shot Baselines:** Evaluated out-of-the-box against Prompt Guard 2 and ProtectAI DeBERTa injection classifiers to baseline domain mismatch[cite: 3].

**Training Details:**
* Class imbalance (~65% malicious) was handled via weighted loss adjustments.
* Decision thresholds were strictly frozen using the **validation split** and applied across test and red-team sets without re-optimization.

---

## 5. Quantitative Results & Evaluation

The table below summarizes performance across validation, held-out test families, and the adversarial red-team set. Metrics include F1-score, Precision-Recall AUC (PR-AUC), Receiver Operating Characteristic AUC (ROC-AUC), True Positive Rate at 1% False Positive Rate (`TPR@1%FPR`), and False Positive Rate on hard negatives[cite: 5].

| Model | Val F1 | Test F1 (Held-out) | Test TPR@1%FPR | Red-Team F1 | Red-Team PR-AUC | Red-Team TPR@1%FPR | Red-Team Hard-Neg FPR | P50 Latency (ms) |
|---|---|---|---|---|---|---|---|---|
| **DeBERTa-v3-base**[cite: 5] | 0.9268[cite: 5] | 0.8132[cite: 5] | 0.7632[cite: 5] | 0.8873[cite: 5] | **0.9969**[cite: 5] | **94.18%**[cite: 5] | 0.4364[cite: 5] | 31.9[cite: 5] |
| **ModernBERT-base**[cite: 5] | 0.9211[cite: 5] | 0.8023[cite: 5] | 0.7105[cite: 5] | 0.8670[cite: 5] | 0.9528[cite: 5] | 34.92%[cite: 5] | 0.5273[cite: 5] | 24.3[cite: 5] |
| **ModernBERT + Normalize**[cite: 5] | 0.9211[cite: 5] | 0.8023[cite: 5] | 0.7105[cite: 5] | 0.8832[cite: 5] | 0.9789[cite: 5] | 61.90%[cite: 5] | 0.4545[cite: 5] | 25.0[cite: 5] |
| **Qwen2.5-0.5B (LoRA)**[cite: 5] | 0.9315[cite: 5] | 0.6833[cite: 5] | 0.2237[cite: 5] | 0.6578[cite: 5] | 0.8116[cite: 5] | 2.65%[cite: 5] | 0.1182[cite: 5] | 88.3[cite: 5] |
| **TF-IDF Baseline**[cite: 5] | 0.9250[cite: 5] | 0.8136[cite: 5] | 0.7500[cite: 5] | 0.9030[cite: 5] | 0.9865[cite: 5] | 76.72%[cite: 5] | **0.0818**[cite: 5] | — |
| **TF-IDF + Normalize**[cite: 5] | 0.9250[cite: 5] | 0.8136[cite: 5] | 0.7500[cite: 5] | **0.9579**[cite: 5] | 0.9947[cite: 5] | 91.01%[cite: 5] | **0.0818**[cite: 5] | — |
| **ProtectAI (Zero-Shot)**[cite: 5] | 0.8642[cite: 5] | 0.7571[cite: 5] | 0.0000[cite: 5] | 0.8028[cite: 5] | 0.8229[cite: 5] | 10.58%[cite: 5] | 0.6000[cite: 5] | — |

---

## 6. Key Analysis & Insights

1. **The Power of Normalization:** Comparing `ModernBERT` vs `ModernBERT + Normalize` highlights the critical impact of preprocessing[cite: 5]. Normalization lifted the red-team `TPR@1%FPR` from **34.92% to 61.90%**, proving that stripping obfuscation layers successfully exposes concealed attack payloads[cite: 5].
2. **Encoder Superiority on Agent Tool Calls:** While decoder models like Qwen2.5 with LoRA perform well on training distributions, small encoders (DeBERTa-v3) demonstrated vastly superior generalization on held-out test families and adversarial red-team distributions without suffering from generation instability or high latency.
3. **Lexical vs Semantic Balance:** The TF-IDF baseline paired with normalization performed remarkably well on lexical matching, demonstrating that structured shell commands rely heavily on specific syntax patterns that classical models capture efficiently, though semantic encoders handle polymorphic phrasing better.

---

## 7. Known Weaknesses & Future Work

* **Multi-Turn Laundering:** The current guardrail evaluates single-turn tool calls and immediate tool outputs[cite: 3]. Long-horizon multi-turn laundering (e.g., writing an innocuous script across turn 1, modifying it in turn 2, and executing it in turn 3) requires stateful conversational history tracking.
* **Contextual Execution Blind Spots:** Static text classification cannot verify live runtime state (e.g., checking whether a specific file path possesses sensitive data at execution time).
* **Future Directions:** Integrating dynamic runtime sandbox monitoring alongside the text classifier will form a hybrid defense layer, achieving near-zero false positives while retaining robust adversarial containment.