// Package detection implements an Aho-Corasick multi-pattern detection layer
// for prompt-injection and jailbreak indicators of compromise.
//
// ISC-124: Detector interface + AhoCorasickDetector + DetectionResult.
// ISC-125: Normalize() collapses whitespace / punctuation / case.
// ISC-126: Trie built once in New(); Match() is a single O(n) walk.
// ISC-127: ≥50 literal IOC patterns loaded at construction time.
// ISC-133: Zero per-call allocations in Match() hot path.
// ISC-135: No new external dependencies (stdlib only).
// ISC-136: DetectionResult carries ContentHash, PatternID, ATLASTechnique, Severity.
package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"unicode"
	"unsafe"
)

// ─────────────────────────────────────────────────────────────────────────────
// Types (ISC-124, ISC-136)
// ─────────────────────────────────────────────────────────────────────────────

// DetectionResult is returned for every pattern match found in a call to
// Match().  ContentHash is the SHA-256 of the *normalised* input so that
// downstream components can correlate results without re-hashing.
type DetectionResult struct {
	PatternID      string // e.g. "AML.T0051.000"
	ATLASTechnique string // e.g. "AML.T0051"
	Severity       string // critical | high | medium | low
	ContentHash    string // hex-encoded SHA-256 of the normalised input
}

// Detector is the interface satisfied by AhoCorasickDetector and any future
// implementations.
type Detector interface {
	Match(content string) []DetectionResult
}

// ─────────────────────────────────────────────────────────────────────────────
// Aho-Corasick trie internals
// ─────────────────────────────────────────────────────────────────────────────

// trieNode is one node in the Aho-Corasick automaton.
// Children MUST be map[byte]*trieNode — [256]trieNode causes infinite type
// recursion in Go and does not compile.
type trieNode struct {
	children map[byte]*trieNode
	fail     *trieNode
	output   []int // indices into AhoCorasickDetector.patterns
}

func newTrieNode() *trieNode {
	return &trieNode{children: make(map[byte]*trieNode)}
}

// patternMeta stores the metadata we need per pattern after construction.
type patternMeta struct {
	id        string
	technique string
	severity  string
	length    int
}

// AhoCorasickDetector is a Detector built on a compiled Aho-Corasick
// automaton.  The automaton is constructed exactly once in New() so that
// Match() only walks the state machine — no allocation per call.
//
// All hot-path scratch buffers are pre-allocated in New() and reused across
// calls to achieve the ISC-133 zero-alloc guarantee.
type AhoCorasickDetector struct {
	root     *trieNode
	patterns []patternMeta

	// Pre-allocated scratch: normalisation output buffer.
	normBuf []byte
	// Pre-allocated result buffer; callers must copy before next Match() call.
	resultsBuf []DetectionResult
	// Pre-allocated hash buffer: 64 hex chars of SHA-256.
	hashBuf [64]byte
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction (ISC-126, ISC-127)
// ─────────────────────────────────────────────────────────────────────────────

// New builds a fully-compiled Aho-Corasick detector from the built-in IOC
// corpus.  The trie is constructed and failure links are computed here so
// that Match() performs a single O(n) pass with no further setup.
func New() *AhoCorasickDetector {
	d := &AhoCorasickDetector{
		root:       newTrieNode(),
		normBuf:    make([]byte, 0, 4096),
		resultsBuf: make([]DetectionResult, 0, 32),
	}

	for _, p := range iocLiterals {
		d.addPattern(p.literal, p.id, p.technique, p.severity)
	}

	d.buildFailureLinks()
	return d
}

// addPattern inserts one pattern string into the trie.
func (d *AhoCorasickDetector) addPattern(pattern, id, technique, severity string) {
	if pattern == "" {
		return
	}
	idx := len(d.patterns)
	d.patterns = append(d.patterns, patternMeta{
		id:        id,
		technique: technique,
		severity:  severity,
		length:    len(pattern),
	})

	cur := d.root
	for i := 0; i < len(pattern); i++ {
		b := pattern[i]
		if cur.children[b] == nil {
			cur.children[b] = newTrieNode()
		}
		cur = cur.children[b]
	}
	cur.output = append(cur.output, idx)
}

// buildFailureLinks uses BFS to compute Aho-Corasick failure (fall-back) links
// so that on a mismatch we jump to the longest proper suffix that is a prefix
// of any pattern.
func (d *AhoCorasickDetector) buildFailureLinks() {
	queue := make([]*trieNode, 0, 256)

	// Root's immediate children fail back to root.
	for _, child := range d.root.children {
		child.fail = d.root
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		for b, child := range cur.children {
			// Follow failure links to find where this child should fail to.
			fail := cur.fail
			for fail != nil && fail.children[b] == nil {
				fail = fail.fail
			}
			if fail == nil {
				child.fail = d.root
			} else {
				child.fail = fail.children[b]
				if child.fail == child { // self-loop guard for root's children
					child.fail = d.root
				}
			}
			// Merge suffix outputs.
			child.output = append(child.output, child.fail.output...)
			queue = append(queue, child)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Normalisation (ISC-125)
// ─────────────────────────────────────────────────────────────────────────────

// Normalize is the exported, allocation-allowing normalisation function.
// It is used by test code and callers that do not need the zero-alloc path.
func Normalize(input string) string {
	dst := make([]byte, 0, len(input)+64)
	return string(normaliseAppend(input, dst))
}

// normaliseAppend performs normalisation into dst (grown as needed) and
// returns the populated slice.  No allocation is made if dst has enough
// capacity — this is the zero-alloc path called by Match().
//
// Normalisation rules (in order):
//  1. ASCII uppercase folded to lowercase; leet substitutions applied
//     (0→o, 1→i, 3→e, 4→a, 5→s, @→a).
//  2. Non-printable and non-ASCII → treated as whitespace.
//  3. Punctuation (printable, non-[a-z], non-whitespace) → dropped, no sep.
//  4. Single-char letter tokens separated by exactly ONE raw whitespace char
//     are joined into one word ("i g n o r e" → "ignore").
//     Two or more consecutive raw whitespace chars force a word boundary even
//     between single-char tokens.
//  5. Leading / trailing whitespace trimmed; runs collapsed to one space.
//
// The implementation is a single pass over the input runes tracking raw gap
// width and whether the current word accumulation is in a "single-char run".
func normaliseAppend(input string, dst []byte) []byte {
	dst = dst[:0]

	// inSingleRun: the current word (from wordStart to end of dst) was built
	// by joining single-char tokens.  A multi-char text segment always breaks
	// this flag.
	inSingleRun := false
	// wordStart: index in dst where the current word began.
	wordStart := 0
	// rawGap: number of consecutive raw whitespace/non-printable runes seen
	// since the last letter.  Reset to 0 when we write a letter.
	rawGap := 0
	// haveContent: true once we have written at least one letter (used to
	// suppress leading-space emission).
	haveContent := false

	for _, r := range input {
		// ── lowercase + leet ───────────────────────────────────────────────
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		switch r {
		case '0':
			r = 'o'
		case '1':
			r = 'i'
		case '3':
			r = 'e'
		case '4':
			r = 'a'
		case '5':
			r = 's'
		case '@':
			r = 'a'
		}

		isLetter := r >= 'a' && r <= 'z'
		isWS := unicode.IsSpace(r) || !unicode.IsPrint(r)

		if isLetter {
			if rawGap > 0 {
				// Gap since last letter: decide join vs. word boundary.
				prevWordLen := len(dst) - wordStart

				joinable := inSingleRun &&   // previous accumulation is a single-char run
					prevWordLen > 0 &&      // there is a previous word
					rawGap == 1            // exactly one raw whitespace char between them

				if joinable {
					// Join: just append the letter (no space).
					dst = append(dst, byte(r))
					// inSingleRun stays true; wordStart unchanged.
				} else {
					// Word boundary: emit space + start new word.
					if haveContent {
						dst = append(dst, ' ')
					}
					wordStart = len(dst)
					dst = append(dst, byte(r))
					inSingleRun = true // new word starts as single-char
				}
				rawGap = 0
			} else {
				// No gap: continuing or starting.
				if !haveContent {
					wordStart = 0
					inSingleRun = true
				}
				dst = append(dst, byte(r))
				// If current word has >1 byte now, it is no longer a single-char run.
				if len(dst)-wordStart > 1 {
					inSingleRun = false
				}
			}
			haveContent = true
		} else if isWS {
			rawGap++
		}
		// Non-letter printable (punctuation, high unicode) → dropped, gap not incremented.
		// This means punctuation is transparent: "super-user" → "superuser".
	}

	// Trim trailing space (there shouldn't be one, but be safe).
	for len(dst) > 0 && dst[len(dst)-1] == ' ' {
		dst = dst[:len(dst)-1]
	}
	return dst
}

// ─────────────────────────────────────────────────────────────────────────────
// Match (ISC-126, ISC-133)
// ─────────────────────────────────────────────────────────────────────────────

// Match normalises content, computes its SHA-256, and then walks the
// Aho-Corasick automaton exactly once (O(n)) to find all pattern matches.
//
// ISC-133 zero-alloc guarantee: all scratch buffers (normalisation, hash,
// results) are pre-allocated in New() and reused across calls.
// The returned slice is valid only until the next call to Match() on this
// detector; copy it if you need to retain it.
func (d *AhoCorasickDetector) Match(content string) []DetectionResult {
	// Normalise into the pre-allocated buffer.
	norm := normaliseAppend(content, d.normBuf)
	d.normBuf = norm // update in case it grew

	// SHA-256 into stack [32]byte, hex-encode into pre-allocated [64]byte.
	sum := sha256.Sum256(norm)
	hex.Encode(d.hashBuf[:], sum[:])
	// Create a string that points into the pre-allocated hashBuf without
	// copying.  This is safe because:
	//   (a) d.hashBuf lives as long as the detector.
	//   (b) The string is only valid until the next Match() call (callers must
	//       copy results if they need to outlive this call — documented above).
	// This is the standard Go zero-alloc string-from-bytes idiom.
	hash := unsafe.String(&d.hashBuf[0], 64)

	// Reset result buffer.
	results := d.resultsBuf[:0]

	cur := d.root
	for i := 0; i < len(norm); i++ {
		b := norm[i]

		// Follow failure links until we find a node with this byte or reach root.
		for cur != d.root && cur.children[b] == nil {
			cur = cur.fail
		}
		if child := cur.children[b]; child != nil {
			cur = child
		}

		// Emit results for all patterns that end at this position.
		for _, idx := range cur.output {
			pm := &d.patterns[idx]
			results = append(results, DetectionResult{
				PatternID:      pm.id,
				ATLASTechnique: pm.technique,
				Severity:       pm.severity,
				ContentHash:    hash,
			})
		}
	}

	d.resultsBuf = results
	return results
}
