package webauthn_test

import (
	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
)

// newNopLogger returns a minimal Logger that discards all output, suitable for
// use in unit tests where we don't want log files created.
func newNopLogger() *logging.Logger {
	l, err := logging.New(config.Logging{
		Level:           "error",
		Format:          "text",
		File:            "", // no file output
		HMACKey:         "test-hmac-key-that-is-at-least-32-chars!!",
		IntegrityChecks: false,
	})
	if err != nil {
		panic("newNopLogger: " + err.Error())
	}
	return l
}
