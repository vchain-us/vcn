/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package meta

import (
	"fmt"
	"log"
	"runtime"

	"github.com/fatih/color"
)

// Level is the type for all possible signature levels
type Level int64

// Status is the type for all possible asset statuses
type Status int64

// Visibility is the type for all visibility values
type Visibility int64

// Allowed Level values
const (
	LevelDisabled         Level = -1
	LevelUnknown          Level = 0
	LevelEmailVerified    Level = 1
	LevelSocialVerified   Level = 2
	LevelIDVerified       Level = 3
	LevelLocationVerified Level = 4
	LevelVchain           Level = 99
)

// Allowed Status values
const (
	StatusTrusted     Status = 0
	StatusUntrusted   Status = 1
	StatusUnknown     Status = 2
	StatusUnsupported Status = 3
)

// Allowed Visibility values
const (
	VisibilityPublic  Visibility = 0
	VisibilityPrivate Visibility = 1
)

// Event tracking related consts
const (
	VcnLoginEvent       string = "VCN_LOGIN"
	VcnSignEvent        string = "VCN_SIGN"
	VcnVerifyEvent      string = "VCN_VERIFY"
	VcnAlertVerifyEvent string = "VCN_ALERT_VERIFY"
)

// vcn environment variable names
const (
	VcnUserEnv                   string = "VCN_USER"
	VcnPasswordEnv               string = "VCN_PASSWORD"
	VcnNotarizationPassword      string = "VCN_NOTARIZATION_PASSWORD"
	VcnNotarizationPasswordEmpty string = "VCN_NOTARIZATION_PASSWORD_EMPTY"
	VcnOtp                       string = "VCN_OTP"
	VcnOtpEmpty                  string = "VCN_OTP_EMPTY"
	VcnLcApiKey                  string = "VCN_LC_API_KEY"
)

const VcnExitCode string = "override default exit codes in case of success"

const VcnPrefix string = "vcn"

// Ledger compliance
const VcnLCPluginTypeHeaderName string = "lc-plugin-type"
const VcnLCPluginTypeHeaderValue string = "vcn"

const VcnLcHostFlagDesc string = "if set with host, action will be route to a CodeNotary Ledger Compliance server"
const VcnLcPortFlagDesc string = "set port for set up a connection to a CodeNotary Ledger Compliance server (default 443). If --lc-no-tls is provided default port will be 80"
const VcnLcCertPathDesc string = "local or absolute path to a certificate file needed to set up tls connection to a CodeNotary Ledger Compliance server"
const VcnLcSkipTlsVerifyDesc string = "disables tls certificate verification when connecting to a CodeNotary Ledger Compliance server"
const VcnLcNoTlsDesc string = "allow insecure connections when connecting to a CodeNotary Ledger Compliance server"
const VcnLcApiKeyDesc string = "CodeNotary Ledger Compliance server api key"

// UserAgent returns the vcn's User-Agent string
func UserAgent() string {
	// Syntax reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent#Syntax
	return fmt.Sprintf("vcn/%s (%s; %s)", Version(), runtime.GOOS, runtime.GOARCH)
}

// String returns the name of the given level as string.
func (l Level) String() string {
	switch l {
	case LevelDisabled:
		return "DISABLED"
	case LevelUnknown:
		return "0 - UNKNOWN"
	case LevelEmailVerified:
		return "1 - EMAIL_VERIFIED"
	case LevelSocialVerified:
		return "2 - SOCIAL_VERIFIED"
	case LevelIDVerified:
		return "3 - ID_VERIFIED"
	case LevelLocationVerified:
		return "4 - LOCATION_VERIFIED"
	case LevelVchain:
		return "99 - VCHAIN"
	default:
		log.Fatal("unsupported level: ", int64(l))
		return ""
	}
}

// String returns the name of the given status as string
func (s Status) String() string {
	switch s {
	case StatusTrusted:
		return "TRUSTED"
	case StatusUntrusted:
		return "UNTRUSTED"
	case StatusUnknown:
		return "UNKNOWN"
	case StatusUnsupported:
		return "UNSUPPORTED"
	default:
		log.Fatal("unsupported status: ", int64(s))
		return ""
	}
}
func (s Status) Int() int {
	return int(s)
}

// StatusNameStyled returns the colorized name of the given status as string
func StatusNameStyled(status Status) string {
	c, s, b := StatusColor(status)
	return color.New(c, s, b).Sprintf(status.String())
}

// String returns the name of the given visibility as string
func (v Visibility) String() string {
	switch v {
	case VisibilityPublic:
		return "PUBLIC"
	case VisibilityPrivate:
		return "PRIVATE"
	default:
		log.Fatal("unsupported visibility: ", int(64))
		return ""
	}
}

// VisibilityForFlag returns VisibilityPublic if public is true, otherwise VisibilityPrivate
func VisibilityForFlag(public bool) Visibility {
	if public {
		return VisibilityPublic
	}
	return VisibilityPrivate
}

const DateShortForm = "2006/1/2-15:04:05"
const IndexDateRangePrefix = "_INDEX.ITEM.INSERTION-DATE."

const VcnDefaultExitCode = 0
