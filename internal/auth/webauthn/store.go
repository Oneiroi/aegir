package webauthn

import (
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const defaultChallengeTTL = 5 * time.Minute

// CredentialStore maps userID -> []webauthn.Credential; thread-safe.
type CredentialStore struct {
	mu   sync.RWMutex
	data map[string][]webauthn.Credential
}

func NewCredentialStore() *CredentialStore {
	return &CredentialStore{data: make(map[string][]webauthn.Credential)}
}

func (s *CredentialStore) Get(userID string) []webauthn.Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[userID]
}

func (s *CredentialStore) Add(userID string, cred webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[userID] = append(s.data[userID], cred)
}

// UpdateCounter persists the updated sign counter (and clone-warning flag) for the
// credential identified by credID. Called after every successful FinishLogin.
func (s *CredentialStore) UpdateCounter(userID string, updated *webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds := s.data[userID]
	for i := range creds {
		if string(creds[i].ID) == string(updated.ID) {
			creds[i].Authenticator.SignCount = updated.Authenticator.SignCount
			creds[i].Authenticator.CloneWarning = updated.Authenticator.CloneWarning
			creds[i].Flags = updated.Flags
			break
		}
	}
	s.data[userID] = creds
}

// challengeEntry holds the raw challenge bytes and its expiry time.
type challengeEntry struct {
	session *webauthn.SessionData
	expiry  time.Time
}

// ChallengeStore maps a challengeID to SessionData + expiry; single-use and TTL-enforced.
type ChallengeStore struct {
	mu   sync.Mutex
	data map[string]challengeEntry
	ttl  time.Duration
}

func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	if ttl == 0 {
		ttl = defaultChallengeTTL
	}
	return &ChallengeStore{
		data: make(map[string]challengeEntry),
		ttl:  ttl,
	}
}

// Put stores a session under challengeID with a TTL.
func (s *ChallengeStore) Put(challengeID string, session *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[challengeID] = challengeEntry{session: session, expiry: time.Now().Add(s.ttl)}
}

// Take retrieves and deletes the session for challengeID. Returns nil if missing or expired.
// A second call with the same ID always returns nil (single-use).
func (s *ChallengeStore) Take(challengeID string) *webauthn.SessionData {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.data[challengeID]
	if !ok {
		return nil
	}
	delete(s.data, challengeID)
	if time.Now().After(entry.expiry) {
		return nil
	}
	return entry.session
}

// UserStore maps userID -> WebAuthnUser; used to look up users during login/registration.
type UserStore struct {
	mu   sync.RWMutex
	byID map[string]*WebAuthnUser
}

func NewUserStore() *UserStore {
	return &UserStore{byID: make(map[string]*WebAuthnUser)}
}

func (s *UserStore) Get(userID string) (*WebAuthnUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[userID]
	return u, ok
}

func (s *UserStore) Put(u *WebAuthnUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[u.id] = u
}
