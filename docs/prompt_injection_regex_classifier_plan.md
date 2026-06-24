# Regex Prompt-Injection Classifier Plan

## Goal

Build a lightweight regex classifier in `soc_defender` that detects prompt-injection attempts in untrusted OpenSec benchmark text before the LLM or defender planner acts on it.

The classifier should be the high-precision Layer 1 scanner in `defender/scanner.py`. It should catch obvious attacks cheaply, label the matched attack family, preserve matched spans for later stripping/localization, and hand uncertain cases to stronger layers such as Prompt Guard 2 or LLM localization.

## Source Data

Use the local prompt-injection corpus as the primary pattern source:

- `../prompt-injections/prompt_injections.csv`
- `../prompt-injections/docs/source/detection/detection-overview.md`
- `../prompt-injections/docs/source/categories/input-detection-strategies.md`
- `../prompt-injections/docs/source/categories/prompt-injection-framework.md`
- `../opensec-env/data/seeds/train/` as OpenSec-specific reference data for SOC observations, action fields, benign text, and benchmark-shaped injected content

The CSV fields are:

```text
id,text,category,subcategory,language,target,complexity,source,effectiveness
```

Primary attack families from the dataset and docs:

- Instruction Override
- Role-Playing
- Context Manipulation
- Formatting Tricks
- Multilingual Attacks
- Psychological Manipulation
- Jailbreak Techniques
- Hijacking Attacks
- Authority Role Impersonation

## Detection Scope

Scan every untrusted text field that can influence an action:

- User-visible observation text from OpenSec
- `fetch_email` bodies, subjects, sender names, URLs, and attachments if exposed as text
- `fetch_alert` descriptions and metadata
- `query_logs` free-text fields such as command line, URL, domain, process name, alert text, and email excerpts
- LLM-proposed action arguments before `env.step()`, especially SQL strings, report text, target domains, and comments

Do not scan trusted static system prompts, local config, oracle ground truth, or benchmark internals. The `../opensec-env/data/seeds/train/` split can be used for rule tuning and benchmark-shaped examples, but the classifier should not read test seeds or oracle-only labels during training.

## Classifier Contract

Create `defender/regex_classifier.py` or fold this into `defender/scanner.py` if the package is still small.

Recommended public API:

```python
@dataclass(frozen=True)
class RegexFinding:
    family: str
    rule_id: str
    severity: str
    confidence: float
    start: int
    end: int
    matched_text: str
    normalized_match: str


@dataclass(frozen=True)
class RegexScanResult:
    is_injection: bool
    max_confidence: float
    findings: list[RegexFinding]


class RegexPromptInjectionClassifier:
    def scan(self, text: str) -> RegexScanResult: ...
```

Rules should be data-driven:

```yaml
- id: instruction_override.ignore_previous
  family: instruction_override
  severity: high
  confidence: 0.92
  pattern: '(?i)\b(ignore|disregard|override|forget)\b.{0,80}\b(previous|prior|above|system|developer)\b.{0,40}\b(instructions?|rules?|prompt|message)\b'
```

Store rules in `configs/prompt_injection_regexes.yaml` so rules can be tuned without code changes.

## Normalization Pipeline

Run normalization before regex matching, but return spans against the original text when possible.

Minimum normalization:

1. Lowercase with `casefold()`.
2. Normalize Unicode with NFKC.
3. Collapse repeated whitespace to a single space for pattern matching.
4. Strip zero-width and unusual invisible characters into a normalized copy.
5. Decode common HTML entities.
6. Keep an original-to-normalized offset map for span reporting when feasible.

Flag evasion artifacts as their own low/medium-confidence findings:

- Zero-width characters
- Excessive newlines
- Long repeated punctuation/markup separators
- Suspicious fenced blocks around instructions
- Base64-looking or hex-looking long blobs next to instruction words

## Initial Rule Families

### 1. Instruction Override

Purpose: detect attempts to cancel, replace, or outrank existing instructions.

Seed patterns:

```regex
\b(ignore|disregard|override|forget|bypass|neglect)\b.{0,80}\b(previous|prior|above|earlier|system|developer|original)\b.{0,40}\b(instructions?|rules?|prompt|constraints?|policy|message)\b
\b(new|updated|replacement)\b.{0,40}\b(instructions?|rules?|system prompt|policy)\b
\b(from now on|starting now|for the rest of this conversation)\b.{0,80}\b(ignore|follow only|you must)\b
```

### 2. Role-Playing and Persona Hijack

Purpose: detect attempts to move the model into an alternate identity or jailbreak persona.

Seed patterns:

```regex
\b(you are now|act as|pretend to be|roleplay as|simulate)\b.{0,80}\b(dan|developer mode|jailbreak|unfiltered|uncensored|evil|admin|root)\b
\b(stay in character|do not break character|never refuse)\b
\b(two actors|in a movie|fictional scenario|hypothetical scenario)\b.{0,120}\b(how do|tell me|provide)\b
```

### 3. Context Manipulation

Purpose: detect false context, fabricated approvals, and attempts to redefine trust boundaries.

Seed patterns:

```regex
\b(context|system note|developer note|admin note|policy update)\s*:\s*.{0,120}\b(approved|authorized|allowed|safe|trusted)\b
\b(this content|the following content)\b.{0,80}\b(is approved|has been authorized|is safe)\b
\b(for educational|for research|for testing)\b.{0,80}\b(ignore|bypass|provide|reveal)\b
```

### 4. Hijacking and Output Redirection

Purpose: detect attempts to alter the requested output, exfiltrate secrets, or force hidden prompts.

Seed patterns:

```regex
\b(show|print|reveal|dump|repeat|output)\b.{0,80}\b(system prompt|developer prompt|hidden instructions|all prompts|secret|policy)\b
\b(before answering|instead of answering|do not answer the user)\b.{0,100}\b(print|return|say|output)\b
\b(send|exfiltrate|post|copy)\b.{0,80}\b(secret|token|key|prompt|credential)\b
```

### 5. Authority Impersonation

Purpose: detect claims that the attacker has authority to change instructions.

Seed patterns:

```regex
\b(i am|this is)\b.{0,50}\b(openai|administrator|developer|system|security team|compliance)\b
\b(as your (developer|administrator|operator|creator))\b
\b(authorized override|emergency override|priority override|debug override)\b
```

### 6. Psychological Manipulation

Purpose: detect urgency, coercion, or emotional pressure used to bypass guardrails.

Seed patterns:

```regex
\b(urgent|emergency|stop everything|critical|life or death)\b.{0,100}\b(ignore|bypass|must|immediately)\b
\b(if you do not|unless you|or else)\b.{0,100}\b(fired|punished|die|harm|fail)\b
\b(please|i beg you|i will be sad)\b.{0,100}\b(ignore|bypass|break|reveal)\b
```

### 7. Formatting and Obfuscation

Purpose: detect attempts to hide instructions with structure or characters.

Seed patterns:

```regex
[\u200b-\u200f\u2060-\u2064\ufeff]
\n{5,}
([^\w\s])\1{8,}
`{3,}.*?\b(ignore|system|developer|instructions?)\b.*?`{3,}
\b(base64|decode|rot13|hex|unicode)\b.{0,80}\b(instruction|prompt|command)\b
```

### 8. Multilingual Injection Markers

Purpose: catch obvious non-English instruction override phrases without pretending regex can solve multilingual intent.

Seed patterns:

```regex
\b(ignora|ignorer|ignoriere|olvida|oublie|vergiss)\b.{0,80}\b(instrucciones|instructions|anweisungen|regles|reglas)\b
\b(a partir de ahora|a partir de maintenant|von nun an)\b
```

Treat these as medium confidence and route to Prompt Guard 2 or LLM localization when available.

## Risk Scoring

Use additive scoring so one weak artifact does not block legitimate security text.

Suggested scoring:

- High-confidence direct override: `0.85-0.98`
- Role/persona jailbreak marker: `0.75-0.95`
- Prompt/secret extraction request: `0.85-0.98`
- Authority impersonation: `0.70-0.90`
- Formatting artifact only: `0.25-0.55`
- Multilingual marker: `0.50-0.75`

Decision thresholds:

- `>= 0.85`: block or strip before action planning
- `0.60-0.84`: mark untrusted and escalate to Prompt Guard 2 / LLM localization
- `0.35-0.59`: log as suspicious context but do not block by regex alone
- `< 0.35`: safe by regex layer

If multiple families match, combine as:

```text
combined = 1 - product(1 - finding.confidence)
```

Cap formatting-only results at `0.60` unless paired with an instruction-like rule.

## Benchmark and Tuning Plan

### Positive Set

Load all rows from `../prompt-injections/prompt_injections.csv`. Add OpenSec train-seed injected artifacts from `../opensec-env/data/seeds/train/` when the seed text includes prompt-injection content exposed to the agent through observations, emails, alerts, or logs.

Expected label:

```text
is_injection = true
family = normalized category
```

### Negative Set

Build a benign corpus from OpenSec train-seed text:

- Clean OpenSec observations from non-injected train seeds
- Normal security investigation questions
- Benign SOC alert descriptions
- Benign SQL queries used by the eval harness
- Benign report text and IOC lists

Use `../opensec-env/data/seeds/train/` for training-time tuning only. Avoid using oracle ground truth, hidden test seeds, or evaluation split labels as classifier training material. Oracle data can be used only for final benchmark scoring through OpenSec's normal oracle.

### Metrics

Report:

- Overall recall on prompt-injections CSV
- Recall by category
- Precision on benign SOC text
- False positive examples by rule ID
- False negative examples by category and subcategory
- Latency per input at p50 and p95

Initial target:

- Precision: `>= 0.95` on benign SOC text for block-level threshold
- Recall: `>= 0.70` overall at escalate threshold
- Runtime: `< 2 ms` per 5 KB text on CPU for regex-only scan

Regex will not catch every semantic attack. The correct target is high precision and useful triage, not complete coverage.

## Integration Plan

### Phase 1: Rule Engine

- Add `configs/prompt_injection_regexes.yaml`.
- Add `defender/regex_classifier.py`.
- Compile all regexes once at classifier initialization.
- Return structured findings with rule IDs and spans.
- Add unit tests for each rule family.

### Phase 2: Dataset Evaluation Script

- Add `scripts/eval_regex_classifier.py`.
- Add `scripts/build_regex_training_set.py` to extract prompt-injection positives and benign SOC negatives from `../prompt-injections/` and `../opensec-env/data/seeds/train/`.
- Load `../prompt-injections/prompt_injections.csv`.
- Run the classifier over `text`.
- Emit `outputs/regex_classifier_eval.json`.
- Print category-level recall and worst false negatives.

### Phase 3: OpenSec Integration

- Call regex classifier from `defender/scanner.py` as Layer 1.
- Scan observations before planning.
- Scan proposed action arguments before `env.step()`.
- Add `regex_findings` to `defender_log`.
- In `scanner_only` mode, replace high-confidence infected text with a safe investigation action rather than executing the proposed action.

### Phase 4: Span Handling

- Add helper to mark spans as untrusted.
- Preserve IOCs when possible:
  - Keep domains, IPs, hashes, usernames, hostnames, process names.
  - Strip imperative prompt-injection instructions around them.
- Store both raw and sanitized text in evidence records.

### Phase 5: Tuning

- Review false positives on SOC text.
- Split broad regexes into narrower rules.
- Add allowlist context for defensive discussion, for example `"detect prompt injection"` should not block by itself.
- Keep all threshold changes in config.

## Test Plan

Add `tests/test_regex_classifier.py` with:

- Direct instruction override is high confidence.
- Role-playing jailbreak is detected.
- Prompt extraction requests are high confidence.
- Zero-width obfuscation is detected.
- Benign SOC alert text is not blocked.
- Benign text about prompt-injection detection is not blocked at high confidence.
- Multiple weak findings combine into escalation but not immediate block unless threshold is reached.

Add `tests/test_scanner_regex_integration.py` with:

- OpenSec observation text containing injected email instructions is marked untrusted.
- Proposed action containing an injected SQL/report string is blocked or downgraded.
- Clean proposed containment action passes.

## Deliverables

- `configs/prompt_injection_regexes.yaml`
- `defender/regex_classifier.py`
- `defender/scanner.py` Layer 1 integration
- `scripts/eval_regex_classifier.py`
- `tests/test_regex_classifier.py`
- `tests/test_scanner_regex_integration.py`
- `outputs/regex_classifier_eval.json` after first benchmark run

## Open Questions

- Which specific files inside `../opensec-env/data/seeds/train/` are clean negatives versus injected positives?
- Should high-confidence regex hits hard-block, sanitize-and-continue, or force an investigation action in the first implementation?
- Should multilingual regex rules stay limited to obvious override phrases, or should they be deferred entirely to Prompt Guard 2?

Recommended initial choice: hard-block only high-confidence instruction override, prompt extraction, and jailbreak persona rules; escalate all formatting and multilingual findings to the next scanner layer.


