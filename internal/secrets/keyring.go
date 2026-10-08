package secrets

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// errNotFound and errUnsupported match go-keyring's sentinel errors without
// forcing every caller to import that module.
var (
	errNotFound    = keyring.ErrNotFound
	errUnsupported = keyring.ErrUnsupportedPlatform
)

type realKeyring struct{}

func (realKeyring) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (realKeyring) Set(service, user, secret string) error {
	return keyring.Set(service, user, secret)
}

// ErrNotFound is returned by fake keyrings and the OS keyring when the item is absent.
var ErrNotFound = errors.New("secret not found in keyring")
