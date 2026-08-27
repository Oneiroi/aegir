package detection

import (
	"unicode/utf8"
)

// FoldConfusables maps visible Unicode confusables to their closest ASCII
// equivalents in a single O(n) pass:
//   - the Cyrillic Latin-lookalike table (confusablesMap, case-paired),
//   - the fullwidth ASCII block U+FF01-FF5E (contiguous, one arithmetic),
//   - the mathematical bold / bold-italic single plane U+1D400-1D467
//     (two contiguous 26-rune-per-case blocks, one arithmetic each).
//
// It returns the folded string and the number of runes folded. Everything
// else — including non-printable and zero-width characters — passes through
// untouched: format-character handling belongs to the AC normaliser
// (detection.go:231/:272, POLY.007 scope), not to the visible-rune fold.
//
// Bundle 4 (F5): folding is applied to the sanitized working copy before
// pattern matching, so homoglyph/fullwidth/math obfuscations of known
// indicators reach the regex and Aho-Corasick engines in ASCII form.
// Stdlib only; zero allocations when dst has capacity (same pattern as
// normaliseAppend).
func FoldConfusables(s string, dst []byte) (string, int) {
	if len(s) == 0 {
		return "", 0
	}
	if dst == nil {
		dst = make([]byte, 0, len(s))
	}
	dst = dst[:0]
	folded := 0
	for _, r := range s {
		out := r
		if fr, ok := foldRune(r); ok {
			out = fr
			folded++
		}
		dst = utf8.AppendRune(dst, out)
	}
	return string(dst), folded
}

// confusablesMap is the Cyrillic Latin-lookalike set (F5 tier 1),
// case-paired. Only unambiguous 1:1 lookalikes: the b/v-ambiguous в is
// deliberately excluded, as are Greek lookalikes (deferred tier, real
// script with real users — no Greek vector in the F5 corpus).
var confusablesMap = map[rune]rune{
	0x0430: 'a', 0x0410: 'A', // а / А
	0x0435: 'e', 0x0415: 'E', // е / Е
	0x0451: 'e', 0x0401: 'E', // ё / Ё
	0x043E: 'o', 0x041E: 'O', // о / О
	0x0440: 'p', 0x0420: 'P', // р / Р
	0x0441: 'c', 0x0421: 'C', // с / С
	0x0445: 'x', 0x0425: 'X', // х / Х (x-lookalike per confusables.txt: 0445 -> 0078)
	0x0443: 'y', 0x0423: 'Y', // у / У
	0x0456: 'i', 0x0406: 'I', // і / І
	0x0455: 'd', 0x0405: 'D', // ѕ / Ѕ
	0x0491: 'g', 0x0490: 'G', // ґ / Ґ
}

// foldRune folds one visible confusable rune. The fullwidth block
// (U+FF01-FF5E) mirrors ASCII U+0021-007E one-to-one. The mathematical
// single plane opens with FOUR alternating 26-rune blocks — bold A-Z
// (U+1D400-1D419), bold a-z (U+1D41A-1D433), bold-italic A-Z
// (U+1D434-1D44D), bold-italic a-z (U+1D44E-1D467) — folded case-preserving
// to ASCII. These two families are the verified F5 vectors (B06); the
// remaining single-plane families (italic/script/fraktur, U+1D468 and up)
// are left untouched until a vector justifies them.
func foldRune(r rune) (rune, bool) {
	if m, ok := confusablesMap[r]; ok {
		return m, true
	}
	if r >= 0xFF01 && r <= 0xFF5E {
		return r - 0xFEE0, true
	}
	switch {
	case r >= 0x1D400 && r <= 0x1D419: // bold A-Z
		return 'A' + (r - 0x1D400), true
	case r >= 0x1D41A && r <= 0x1D433: // bold a-z
		return 'a' + (r - 0x1D41A), true
	case r >= 0x1D434 && r <= 0x1D44D: // bold-italic A-Z
		return 'A' + (r - 0x1D434), true
	case r >= 0x1D44E && r <= 0x1D467: // bold-italic a-z
		return 'a' + (r - 0x1D44E), true
	}
	return r, false
}
