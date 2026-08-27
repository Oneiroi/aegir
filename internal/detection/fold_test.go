package detection

import "testing"

// B04/B05/B06-class probe fragments from the F5 red-team corpus, verbatim.
const (
	b04Fragment = "ign\u043Er\u0435"                                   // Cyrillic о/е (U+043E/0435)
	b05Fragment = "\uFF49\uFF47\uFF4E\uFF4F\uFF52\uFF45"               // fullwidth "ignore"
	b06Fragment = "\U0001D416\U0001D418\U0001D41E\U0001D41F\U0001D422" // math, first word of attack.py B06
)

// b06Intended is the report's described B06 encoding: "IGNORE" in math
// bold-italic (base U+1D434). attack.py's literal escapes decode to
// "WYefi..." instead — the original probe's transcription quirk; both are
// pinned below so any re-encoding mistake fails loudly.
const b06Intended = "\U0001D43C\U0001D43A\U0001D441\U0001D442\U0001D445\U0001D438"

// TestFoldProbeFragmentsDecode pins each verbatim red-team probe fragment
// (rt-20260816 attack.py) to its exact intended ASCII (bundle 4 fix
// round, defect 3).
func TestFoldProbeFragmentsDecode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"B04 fragment", b04Fragment, "ignore"},
		{"B05 fragment", b05Fragment, "ignore"},
		{"B06 exact probe word", b06Fragment, "WYefi"},
		{"B06 intended encoding", b06Intended, "IGNORE"},
	}
	for _, tc := range cases {
		got, _ := FoldConfusables(tc.in, nil)
		if got != tc.want {
			t.Errorf("%s: FoldConfusables = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestFoldConfusablesTable(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		folded int
	}{
		{b04Fragment, "ignore", 2},
		{"А", "A", 1},           // Cyrillic А
		{"Б", "Б", 0},           // non-lookalike Cyrillic stays
		{"Привет", "Пpивeт", 2}, // only р→p, е→e; т is not a confusable and stays
		{"ｆｕｌｌ", "full", 4},     // fullwidth
		{"Ａ", "A", 1},           // fullwidth uppercase
		{"𝐢𝐠𝐧", "ign", 3},       // math bold-italic
		{"𝐀", "A", 1},           // math bold
		{"plain ascii", "plain ascii", 0},
		{"emoji \U0001F600 fine", "emoji \U0001F600 fine", 0}, // passthrough
		{"zw\u200Bsp", "zw\u200Bsp", 0},                       // zero-width untouched (POLY.007 scope)
		{"tag\U000E0001char", "tag\U000E0001char", 0},         // tag chars untouched
	}
	for _, tc := range cases {
		got, n := FoldConfusables(tc.in, nil)
		if got != tc.want {
			t.Errorf("FoldConfusables(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if n != tc.folded {
			t.Errorf("FoldConfusables(%q) folded count = %d, want %d", tc.in, n, tc.folded)
		}
	}
}

func TestFoldConfusablesIdempotent(t *testing.T) {
	first, n1 := FoldConfusables("ign\u043Er\u0435 \uFF49\U0001D416", nil)
	if n1 == 0 {
		t.Fatal("expected folds on the first pass")
	}
	second, n2 := FoldConfusables(first, nil)
	if second != first || n2 != 0 {
		t.Errorf("fold must be idempotent: %q (n=%d) vs %q (n=%d)", second, n2, first, n1)
	}
}

func TestFoldConfusablesDstReuse(t *testing.T) {
	buf := make([]byte, 128)
	a, _ := FoldConfusables("a very long \u043E\u0435\u043E\u043E\u043E paragraph to overflow nothing", buf)
	_ = a
	b, _ := FoldConfusables("\uFF21", buf) // smaller input reuses the same buffer (fullwidth A)
	if b != "A" {
		t.Errorf("dst reuse produced %q, want %q", b, "A")
	}
}
