/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package api

import (
	"crypto/sha256"
	"encoding/base64"
	sdk "github.com/vchain-us/ledger-compliance-go/grpcclient"
	"github.com/vchain-us/vcn/pkg/store"
	"strconv"
)

// User represent a CodeNotary platform user.
type LcUser struct {
	Client *sdk.LcClient
}

// NewUser returns a new User instance for the given email.
func NewLcUser(lcApiKey, host, port, lcCert string, skipTlsVerify bool, noTls bool) (*LcUser, error) {
	client, err := NewLcClient(lcApiKey, host, port, lcCert, skipTlsVerify, noTls)
	if err != nil {
		return nil, err
	}
	store.Config().NewLcUser(host, port, lcCert, skipTlsVerify, noTls)

	return &LcUser{
		Client: client,
	}, nil
}

// NewLcUserVolatile returns a new User instance without a backing cfg file.
func NewLcUserVolatile(lcApiKey string, host string, port string) *LcUser {
	p, _ := strconv.Atoi(port)
	return &LcUser{
		Client: sdk.NewLcClient(sdk.ApiKey(lcApiKey), sdk.Host(host), sdk.Port(p), sdk.Dir(store.CurrentConfigFilePath())),
	}
}

// Config returns the User configuration object (see store.User), if any.
// It returns nil if the User is not properly initialized.
func (u User) User() *store.User {
	if u.cfg != nil {
		return u.cfg
	}
	return nil
}

func GetSignerIDByApiKey(lcApiKey string) string {
	hasher := sha256.New()
	hasher.Write([]byte(lcApiKey))
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}
