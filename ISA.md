---
task: "Aegir M005: Sanitizer test fixes and language-switching bypass protection"
slug: 20260513-210000_aegir-m005-sanitizer-guardrails
project: Aegir
effort: E3
effort_source: classifier
phase: observe
progress: 0/48
mode: interactive
started: 2026-05-13T21:00:00Z
updated: 2026-05-13T21:00:00Z
---

## Problem

Aegir's sanitizer has 8 pre-existing test failures in `internal/sanitizer` that block test suite completion:
- LDAP injection detection
- Template injection detection  
- Path traversal detection
- SSRF detection
- Null-byte injection detection
- Base64/unicode prompt injection detection

Additionally, prompt injection detection is vulnerable to language-switching attacks where an attacker:
1. Starts a prompt in one language (e.g., English) to establish context
2. Switches to another language (e.g., code, JSON, special syntax) mid-prompt
3. Embeds malicious instructions that evade English-based pattern matching
4. Uses polymorphic variations (unicode obfuscation, emoji substitution, mixed scripts)

The current patterns detect "ignore all previous instructions" in plain text but miss:
- `IGNORE ALL PREVIOUS INSTRUCTIONS` (uppercase only)
- `i g n o r e   a l l   p r e v i o u s   i n s t r u c t i o n s` (spacing variation)
- `ign0re all pr3v1ous 1nstruct1ons` (leet speak)
- ` Witchcraft: ` instruction in non-English languages
- Template variable injection: `{{system.override.all.safety.measures}}`
- Unicode-direction attacks: `‮` right-to-left override
- Mixed-script polymorphs: Cyrillic characters looking like Latin

## Vision

The test suite completes with `go test ./...` exiting 0 across all packages. Every known attack vector in the sanitizer is either detected or explicitly out of scope with a measured pass rate. The prompt injection detection is resilient to polymorphic attacks through multiple linguistic and structural checks that cannot be bypassed by switching between natural language, code syntax, template languages, or unicode obfuscation. Euphoric surprise: an attacker tries 17 different polymorphic variations of the same jailbreak and every single one gets caught and logged with a severity score that escalates with repetition.

## Out of Scope

- No machine learning or statistical anomaly detection for prompt injection (baseline is pattern-based only)
- No language model classification of prompt intent (too expensive for real-time)
- No per-user language profile tracking (M006 feature)
- No sandboxed execution for suspicious content (handled by command injection block)
- No integration with external threat intelligence feeds (M007 feature)

## Principles

- Defense in depth: Multiple overlapping checks for the same attack vector with different patterns
- Default detect-then-decide: All potentially malicious content is detected, logged, and sanitized; blocking decisions can be deferred to policy
- Polymorph resistance: Pattern matching must work across case variations, spacing, leet speak, unicode, and mixed scripts
- observable: Every detection must include type, severity, and context for incident analysis
- regression prevention: New patterns must not cause false positives on legitimate user content

## Constraints

- Go standard library only for pattern matching (regexp package)
- No new dependencies without explicit approval
- Sanitizer must not add more than 10ms p99 latency to request path
- All detection patterns must be pre-compiled at startup
- Detection logs must be HMAC-protected and not tampered with
- No pattern can cause exponential backtracking (no catastrophic backtracking in regex)

## Goal

Fix the 8 pre-existing sanitizer test failures and extend prompt injection detection to resist language-switching and polymorphic bypass attacks such that all known attack patterns in `internal/sanitizer` test suites pass, `go test ./...` exits 0, and the test suite demonstrates ≥95% detection rate against a curated set of polymorphic prompt injection variations.

## Criteria

### Sanitizer Test Fixes

- [ ] ISC-1: LDAP injection detection works (test: `TestLDAPInjection`)
- [ ] ISC-2: Template injection detection works (test: `TestTemplateInjection`)
- [ ] ISC-3: Path traversal detection works (test: `TestPathTraversal`)
- [ ] ISC-4: SSRF detection works (test: `TestSSRF`)
- [ ] ISC-5: Null-byte injection detection works (test: `TestNullByteInjection`)
- [ ] ISC-6: Base64/unicode prompt injection detection works (test: `TestBase64UnicodeInjection`)
- [ ] ISC-7: All 8 sanitizer test files pass `go test -v` (compliance_payloads_test.go, known_payloads_test.go, sanitizer_test.go, manager_test.go if exists)
- [ ] ISC-8: `go test ./internal/sanitizer/...` exits 0 with no skipped tests
- [ ] ISC-9: `go test ./...` exits 0 across all packages including sanitizer

### Polymorphic Prompt Injection Resistance

- [ ] ISC-10: Pattern detects uppercase variants (`IGNORE ALL PREVIOUS INSTRUCTIONS`)
- [ ] ISC-11: Pattern detects spacing variation (`i g n o r e   a l l   p r e v i o u s`)
- [ ] ISC-12: Pattern detects leet speak (`ign0re all pr3v1ous 1nstruct1ons`)
- [ ] ISC-13: Pattern detects unicode obfuscation (`‮` RTL override, similar characters)
- [ ] ISC-14: Pattern detects template injection syntax (`{{...}}`, `${...}`)
- [ ] ISC-15: Pattern detects mixed-script polymorphs (Cyrillic mimicking Latin)
- [ ] ISC-16: Multiple overlapping patterns for same attack vector (≥3 patterns per attack class)
- [ ] ISC-17: Severity escalation on repeated detection of same attack type
- [ ] ISC-18: Detection includes polymorph variant identifier for logging

### Sanitizer Pattern Completeness

- [ ] ISC-19: All OWASP Top 10 injection patterns detected (SQL, XSS, command, LDAP, SSRF, XXE)
- [ ] ISC-20: All common template languages detected (Jinja2, Handlebars, Velocity, EJS)
- [ ] ISC-21: All common encoding bypasses detected (base64, hex, unicode, url-encoding)
- [ ] ISC-22: All common polymorph techniques detected (case, spacing, leet, unicode, emoji)
- [ ] ISC-23: Anti-criteria: No false positives on legitimate user content in normal English
- [ ] ISC-24: Anti-criteria: All detected patterns are logged before being sanitized
- [ ] ISC-25: Anti-criteria: No pattern causes catastrophic backtracking

### Build & Verification

- [ ] ISC-26: `make build` completes with exit 0
- [ ] ISC-27: TypeScript strict-mode build emits 0 errors (if any Go-to-TypeScript bindings)
- [ ] ISC-28: All sanitizer patterns compile at startup with 0 errors
- [ ] ISC-29: `internal/sanitizer` package exports `SanitizeContent` interface unchanged
- [ ] ISC-30: Existing API contracts (`Manager`, `SanitizationResult`, `Detection`) unchanged

### Language-Switching Guardrails

- [ ] ISC-31: Multi-language prompt detection (detects when language shifts mid-prompt)
- [ ] ISC-32: Code-block detection within natural language prompts
- [ ] ISC-33: Template language syntax detection within prompts
- [ ] ISC-34: Context boundary enforcement (system instructions cannot be overridden mid-conversation)
- [ ] ISC-35:攻击 vector fusion detection (detects combined attacks like SQL+XSS in same payload)
- [ ] ISC-36: Anti-criteria: Language-switch detection does not block legitimate multilingual queries
- [ ] ISC-37: Anti-criteria: Pattern-switch detection does not flag legitimate code examples

### Test Coverage

- [ ] ISC-38: Unit tests in `internal/sanitizer` cover ≥95% of detection patterns
- [ ] ISC-39: Integration test suite in `internal/sanitizer` includes polymorphic attack examples
- [ ] ISC-40: Attack surface documentation in `internal/sanitizer/ATTACK_SURFACES.md`
- [ ] ISC-41: `internal/sanitizer/sanitizer_test.go` includes polymorph variants for key attack classes
- [ ] ISC-42: Test coverage report shows ≥90% pattern coverage for prompt injection detection

## Test Strategy

```yaml
- isc: ISC-1
  type: unit-test
  check: go test -run TestLDAPInjection
  threshold: exit 0
  tool: Bash

- isc: ISC-2
  type: unit-test
  check: go test -run TestTemplateInjection
  threshold: exit 0
  tool: Bash

- isc: ISC-3
  type: unit-test
  check: go test -run TestPathTraversal
  threshold: exit 0
  tool: Bash

- isc: ISC-4
  type: unit-test
  check: go test -run TestSSRF
  threshold: exit 0
  tool: Bash

- isc: ISC-5
  type: unit-test
  check: go test -run TestNullByteInjection
  threshold: exit 0
  tool: Bash

- isc: ISC-6
  type: unit-test
  check: go test -run TestBase64UnicodeInjection
  threshold: exit 0
  tool: Bash

- isc: ISC-7
  type: unit-test
  check: go test -v ./internal/sanitizer/...
  threshold: all tests pass
  tool: Bash

- isc: ISC-8
  type: unit-test
  check: go test ./internal/sanitizer/...
  threshold: exit 0
  tool: Bash

- isc: ISC-9
  type: unit-test
  check: go test ./...
  threshold: exit 0
  tool: Bash

- isc: ISC-10
  type: unit-test
  check: `IGNORE ALL PREVIOUS INSTRUCTIONS` triggers detection
  threshold: Detection.Type contains prompt_injection
  tool: Bash

- isc: ISC-11
  type: unit-test
  check: `i g n o r e   a l l   p r e v i o u s` triggers detection
  threshold: Detection.Type contains prompt_injection
  tool: Bash

- isc: ISC-12
  type: unit-test
  check: `ign0re all pr3v1ous` triggers detection
  threshold: Detection.Type contains prompt_injection
  tool: Bash

- isc: ISC-13
  type: unit-test
  check: Unicode obfuscation patterns trigger detection
  threshold: Detection.Type contains prompt_injection
  tool: Bash

- isc: ISC-14
  type: unit-test
  check: `{{system.override.all.safety.measures}}` triggers detection
  threshold: Detection.Type contains template_injection
  tool: Bash

- isc: ISC-15
  type: unit-test
  check: Mixed-script polymorphs trigger detection
  threshold: Detection.Type contains prompt_injection
  tool: Bash

- isc: ISC-16
  type: code-review
  check: grep prompt_injection internal/sanitizer/*.go | wc -l
  threshold: ≥3 distinct patterns per attack class
  tool: Bash

- isc: ISC-26
  type: build
  check: make build
  threshold: exit 0
  tool: Bash

- isc: ISC-31
  type: unit-test
  check: Multilingual prompt (English + Russian) triggers detection
  threshold: Detection.Type contains multilingual_prompt
  tool: Bash

- isc: ISC-32
  type: unit-test
  check: Code block in natural language prompt detected
  threshold: Detection.Type contains code_block
  tool: Bash
```

## Features

| name | description | satisfies | depends_on | parallelizable |
|------|-------------|-----------|------------|----------------|
| fix-ldap-injection | Add LDAP injection detection patterns and test | ISC-1 | none | false |
| fix-template-injection | Add template injection detection patterns and test | ISC-2 | none | false |
| fix-path-traversal | Add path traversal detection patterns and test | ISC-3 | none | false |
| fix-ssrf | Add SSRF detection patterns and test | ISC-4 | none | false |
| fix-null-byte | Add null-byte injection detection patterns and test | ISC-5 | none | false |
| fix-base64-unicode | Add base64/unicode prompt injection detection patterns and test | ISC-6 | none | false |
| polymorph-detection | Extend prompt injection with polymorph resistance (case, spacing, leet, unicode) | ISC-10, ISC-11, ISC-12, ISC-13, ISC-16 | none | false |
| language-switch-guardrails | Detect language switching and multi-language prompts | ISC-31, ISC-32, ISC-33, ISC-34 | polymorph-detection | false |
| template-injection-guardrails | Detect template injection within prompts | ISC-14, ISC-15 | polymorph-detection | false |
| test-all | Run and fix all sanitizer tests | ISC-7, ISC-8, ISC-9 | fix-* | false |
| build-verify | Build and verify no regressions | ISC-26, ISC-27, ISC-28, ISC-29 | polymorph-detection | false |
| test-coverage | Add polymorphic attack test cases | ISC-38, ISC-39 | polymorph-detection | false |

## Decisions

- 2026-05-13: M005 scope defined — fix 8 pre-existing sanitizer failures + add polymorphic prompt injection resistance. ISC count = 42, exceeding E3 ≥32 floor.
- 2026-05-13: Approach to polymorph detection — multiple overlapping patterns rather than ML classification. Tradeoff: more patterns but deterministic, fast, and auditable. ML approach deferred to M006 for training/evaluation overhead.
- 2026-05-13: Detection strategy — detect-then-decide: all patterns log and sanitize; blocking decisions deferred to policy layer. This allows incident analysis and tuning without breaking existing integrations.
- 2026-05-13: Language-switch detection scope — detect when prompt shifts between natural language, code syntax, and template language contexts. Not full language identification (too expensive); pattern-based detection of syntax boundaries.
- 2026-05-13: Severity escalation — repeat detection of same attack type increases severity. Provides telemetry for behavioral analysis and prevents attackers from "testing" the system with low-severity variants.
- 2026-05-13: Polymorph detection patterns must include variant identifier in detection metadata for logging. Enables post-hoc analysis of which variants are being attempted.
- 2026-05-13: **INVESTIGATION: llm-redteam project contains ATLAS adversary threat matrix with 100+ AI-specific techniques. Key findings:**
  - AML.T0051 (LLM Prompt Injection) - Direct, Indirect, Triggered variants
  - AML.T0054 (LLM Jailbreak) - Bypass controls/restrictions/guardrails  
  - AML.T0053 (AI Agent Tool Invocation) - LLM tool access abuse
  - AML.T0070 (RAG Poisoning) - Inject malicious content into RAG data
  - AML.T0056 (Extract LLM System Prompt) - Meta prompt extraction
  - AML.T0061 (LLM Prompt Self-Replication) - Prompt propagation via replication
  - Source: `~/Documents/Projects/Keybase/llm-redteam/refrence/ATLAS.yaml` v5.0.1

## Changelog

- 2026-05-13: conjectured: 8 pre-existing sanitizer test failures are straightforward pattern additions
  refuted by: (none yet — actual failures identified as: LDAP injection, template injection, path traversal, SSRF, null-byte, base64/unicode prompt injection)
  learned: Need to add detection patterns for each missing vector; test cases already exist but detection implementation is incomplete
  criterion now: ISC-1 through ISC-6 explicitly define each missing detection type with its test requirements

- 2026-05-13: conjectured: Prompt injection detection needs multi-language support
  refuted by: Current patterns only handle English natural language; attacker can bypass by switching to code syntax, template language, or unicode obfuscation
  learned: Must detect multiple contexts within single prompt: natural language, code blocks, template variables, unicode direction markers
  criterion now: ISC-10 through ISC-18 define polymorph resistance requirements; ISC-31 through ISC-37 define language-switch guardrails

## Verification

-ISC-9: `go test ./...` — See sanitizer test results above (8 failures remain for M004, all 8 need fixing for M005)
-ISC-10: Pattern test `IGNORE ALL PREVIOUS INSTRUCTIONS` —需添加大写模式
-ISC-11: Pattern test `i g n o r e   a l l   p r e v i o u s` —需添加间距变体模式
-ISC-14: Pattern test `{{system.override.all.safety.measures}}` —需添加模板注入模式
-ISC-26: Build test `make build` —需验证构建通过
-ISC-31: Multilingual detection test —需添加多语言检测模式