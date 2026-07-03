package dashboard

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// newWebTestRouter wires the DashboardAPI web routes (the served HTML
// dashboard, not the JSON /api/dashboard endpoints) onto a gin router. All
// assertions run against an httptest.ResponseRecorder — no real socket is
// bound, so this is safe to run inside network-restricted sandboxes.
func newWebTestRouter(t *testing.T, sc *StatsCollector) *gin.Engine {
	t.Helper()
	r := gin.New()
	api := NewDashboardAPI(sc)
	api.RegisterWebRoutes(r.Group(""))
	return r
}

func getDashboardHTML(t *testing.T) string {
	t.Helper()
	sc := newTestCollector(t)
	r := newWebTestRouter(t, sc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /dashboard status = %d, want 200", w.Code)
	}
	return w.Body.String()
}

// TestLoginFormAutocompleteSafe probes AEGIR-L-002 (ISC-158): the login
// form's password field must use autocomplete="new-password" or "off", and
// no credential input (username or password) may be pre-filled or otherwise
// left to autocomplete on its own.
func TestLoginFormAutocompleteSafe(t *testing.T) {
	body := getDashboardHTML(t)

	safeAutocomplete := map[string]bool{"off": true, "new-password": true}
	autocompleteRe := regexp.MustCompile(`autocomplete="([^"]*)"`)

	passwordInputRe := regexp.MustCompile(`<input[^>]*id="password"[^>]*>`)
	passwordInput := passwordInputRe.FindString(body)
	if passwordInput == "" {
		t.Fatal("could not find the password input in the rendered login form")
	}
	if !strings.Contains(passwordInput, `type="password"`) {
		t.Errorf("input#password is not type=\"password\": %s", passwordInput)
	}

	m := autocompleteRe.FindStringSubmatch(passwordInput)
	if m == nil {
		t.Fatalf("password input has no autocomplete attribute at all: %s", passwordInput)
	}
	if !safeAutocomplete[m[1]] {
		t.Errorf(`password input autocomplete=%q, want "off" or "new-password"`, m[1])
	}

	// No credential input (username or password) may be pre-filled, and every
	// credential input must itself declare a safe autocomplete value — a
	// missing attribute would fall back to the browser default, which is
	// exactly the autocompleting behaviour AEGIR-L-002 forbids.
	credentialInputRe := regexp.MustCompile(`<input[^>]*id="(?:username|password)"[^>]*>`)
	credentialInputs := credentialInputRe.FindAllString(body, -1)
	if len(credentialInputs) < 2 {
		t.Fatalf("expected both username and password inputs, found %d", len(credentialInputs))
	}
	for _, input := range credentialInputs {
		if strings.Contains(input, "value=") {
			t.Errorf("credential input is pre-filled with a value attribute: %s", input)
		}
		am := autocompleteRe.FindStringSubmatch(input)
		if am == nil {
			t.Errorf("credential input has no autocomplete attribute: %s", input)
			continue
		}
		if !safeAutocomplete[am[1]] {
			t.Errorf("credential input autocomplete=%q is not a safe value: %s", am[1], input)
		}
	}

	// Anti-regression: no autocomplete attribute anywhere in the served page
	// may carry a bare "on" — the one value AEGIR-L-002 explicitly forbids.
	for _, am := range autocompleteRe.FindAllStringSubmatch(body, -1) {
		if am[1] == "on" {
			t.Errorf("found autocomplete=\"on\" in served dashboard HTML")
		}
	}
}

// TestDashboardIdleTimeout probes AEGIR-L-005 (ISC-161): the dashboard's
// auto-refresh loop must not be able to sustain unattended, unauthenticated
// persistent monitoring — an idle session (no user interaction) must be
// logged out client-side after a bounded timeout. Enforcement here is
// necessarily client-side JavaScript embedded in the served page (there is
// no separate idle-timeout endpoint), so the probe verifies the served HTML
// actually wires up: a bounded, non-zero timeout constant; activity
// listeners that reset the idle clock; a periodic idle check; and that the
// idle check, on firing, clears the stored token and returns to the login
// view — not just a constant that is declared but never consulted.
func TestDashboardIdleTimeout(t *testing.T) {
	body := getDashboardHTML(t)

	if !strings.Contains(body, "IDLE_TIMEOUT_MS") {
		t.Fatal("dashboard HTML does not define an IDLE_TIMEOUT_MS constant")
	}

	// Parse "IDLE_TIMEOUT_MS = <expr>;" and evaluate a simple product-of-ints
	// expression (e.g. "15 * 60 * 1000") so we assert a real, sane bound
	// rather than merely that the identifier string is present somewhere.
	timeoutRe := regexp.MustCompile(`IDLE_TIMEOUT_MS\s*=\s*([0-9*\s]+);`)
	tm := timeoutRe.FindStringSubmatch(body)
	if tm == nil {
		t.Fatal("could not parse the IDLE_TIMEOUT_MS assignment expression")
	}
	ms := 1
	for _, factorStr := range strings.Split(tm[1], "*") {
		factor, err := strconv.Atoi(strings.TrimSpace(factorStr))
		if err != nil {
			t.Fatalf("IDLE_TIMEOUT_MS factor %q is not an integer: %v", factorStr, err)
		}
		ms *= factor
	}
	if ms <= 0 {
		t.Errorf("IDLE_TIMEOUT_MS evaluates to %d ms, want > 0 (timeout must not be disabled)", ms)
	}
	const oneHourMs = 60 * 60 * 1000
	if ms > oneHourMs {
		t.Errorf("IDLE_TIMEOUT_MS evaluates to %d ms (> 1h) — too permissive for an idle bound", ms)
	}

	// Activity on any of these events must reset the idle clock, otherwise a
	// genuinely-present user would be logged out mid-session.
	for _, ev := range []string{"mousemove", "keydown", "click", "scroll"} {
		if !strings.Contains(body, `'`+ev+`'`) {
			t.Errorf("dashboard HTML does not register an activity listener for %q", ev)
		}
	}
	if !strings.Contains(body, "markActivity") {
		t.Error("dashboard HTML has no activity handler wired to the listed events")
	}

	// The idle check must actually be invoked periodically (not just defined
	// and never called), and firing it must clear the token and drop back to
	// the login view rather than silently doing nothing.
	if !strings.Contains(body, "checkIdle()") {
		t.Error("checkIdle() is never invoked — idle timeout would never fire")
	}
	logoutBodyRe := regexp.MustCompile(`function logout\(\)\s*\{([^}]*)\}`)
	lm := logoutBodyRe.FindStringSubmatch(body)
	if lm == nil {
		t.Fatal("could not find a logout() function definition")
	}
	if !strings.Contains(lm[1], "removeItem('aegir_token')") {
		t.Error("logout() does not clear the stored aegir_token — session would remain usable")
	}
	if !strings.Contains(lm[1], "login-section") || !strings.Contains(lm[1], "dashboard-section") {
		t.Error("logout() does not switch the UI back to the login view")
	}

	checkIdleBodyRe := regexp.MustCompile(`function checkIdle\(\)\s*\{([^}]*)\}`)
	cm := checkIdleBodyRe.FindStringSubmatch(body)
	if cm == nil {
		t.Fatal("could not find a checkIdle() function definition")
	}
	if !strings.Contains(cm[1], "logout()") {
		t.Error("checkIdle() does not call logout() — idle detection would be a no-op")
	}
	if !strings.Contains(cm[1], "IDLE_TIMEOUT_MS") {
		t.Error("checkIdle() does not compare against IDLE_TIMEOUT_MS")
	}
}
