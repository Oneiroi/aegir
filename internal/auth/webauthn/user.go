package webauthn

import (
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser implements the webauthn.User interface for Aegir users.
type WebAuthnUser struct {
	id          string
	name        string
	displayName string
	credentials []gowebauthn.Credential
}

// NewWebAuthnUser constructs a WebAuthnUser. Pass nil for credentials when first creating the user.
func NewWebAuthnUser(id, name, displayName string, credentials []gowebauthn.Credential) *WebAuthnUser {
	if credentials == nil {
		credentials = []gowebauthn.Credential{}
	}
	return &WebAuthnUser{
		id:          id,
		name:        name,
		displayName: displayName,
		credentials: credentials,
	}
}

func (u *WebAuthnUser) WebAuthnID() []byte          { return []byte(u.id) }
func (u *WebAuthnUser) WebAuthnName() string         { return u.name }
func (u *WebAuthnUser) WebAuthnDisplayName() string  { return u.displayName }
func (u *WebAuthnUser) WebAuthnCredentials() []gowebauthn.Credential { return u.credentials }
