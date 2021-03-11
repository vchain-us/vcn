/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/vchain-us/vcn/internal/logs"
	"github.com/vchain-us/vcn/pkg/meta"
)

func PromptMnemonic() (mnemonic string, err error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Mnemonic code:")
	if mnemonic, err = reader.ReadString('\n'); err == nil {
		mnemonic = strings.TrimSpace(mnemonic)
	} else {
		mnemonic = ""
	}
	return
}

func PromptPassphrase() (passphrase string, err error) {

	color.Set(meta.StyleAffordance())
	fmt.Print(`
Attention: If you lose this password you will not able to recover it anymore.
This password protects your secret against unauthorized access.
You will need it every time you want to notarize an asset.
`)
	color.Unset()
	fmt.Println()

	var keystorePassphrase string
	var keystorePassphrase2 string

	match := false
	counter := 0
	for match == false {

		counter++

		if counter == 4 {
			return "", fmt.Errorf("too many failed attempts")
		}

		keystorePassphrase, _ = readPassword("Notarization password: ")
		keystorePassphrase2, _ = readPassword("Notarization password (reenter): ")
		fmt.Println()

		if keystorePassphrase != keystorePassphrase2 {
			fmt.Println("Your two inputs did not match. Please try again.")
		} else {
			match = true
		}

	}
	return keystorePassphrase, nil
}

func ProvidePassphrase() (passphrase string, interactive bool, err error) {
	if _, empty := os.LookupEnv(meta.VcnNotarizationPasswordEmpty); empty {
		logs.LOG.Trace("Empty notarization password provided (environment)")
		return "", false, nil
	}
	passphrase, ok := os.LookupEnv(meta.VcnNotarizationPassword)
	if ok {
		logs.LOG.Trace("Notarization password provided (environment)")
		return passphrase, false, nil
	}
	fmt.Println("Please enter you notarization password to notarize your asset.\nIf you did not set a separate notarization password, use the one used to log in.")
	passphrase, err = readPassword("Password: ")
	if err != nil {
		return "", true, err
	}
	logs.LOG.Trace("Notarization password provided (interactive)")
	return passphrase, true, nil
}

func ProvidePasswordWithMessage(message string) (passphrase string, err error) {
	passphrase, err = readPassword(message)
	if err != nil {
		return "", err
	}
	logs.LOG.Trace("Password provided (interactive)")
	return passphrase, nil
}

func ProvidePlatformUsername() (user string, err error) {
	user = os.Getenv(meta.VcnUserEnv)
	if user != "" {
		logs.LOG.WithFields(logrus.Fields{
			"username": user,
		}).Trace("Platform user provided (environment)")
		return user, nil
	}
	fmt.Print("Email address: ")
	n, err := fmt.Scanln(&user)
	if n <= 0 {
		return "", fmt.Errorf("email address must not be empty")
	}
	if err != nil {
		return "", err
	}
	user = strings.TrimSpace(user)
	logs.LOG.WithFields(logrus.Fields{
		"username": user,
	}).Trace("Platform user provided (interactive)")
	return user, nil
}

func ProvidePlatformPassword() (password string, err error) {
	password = os.Getenv(meta.VcnPasswordEnv)
	if password != "" {
		logs.LOG.Trace("Platform password provided (environment)")
		return password, nil
	}
	password, err = readPassword("Login password: ")
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	logs.LOG.Trace("Platform password provided (interactive)")
	return password, nil
}

func ProvideOtp() (otp string, err error) {
	if _, empty := os.LookupEnv(meta.VcnOtpEmpty); empty {
		logs.LOG.Trace("Empty otp provided (environment)")
		return "", nil
	}
	otp = os.Getenv(meta.VcnOtp)
	if otp != "" {
		logs.LOG.Trace("Otp provided (environment)")
		return otp, nil
	}
	fmt.Print("One time password (press enter if null): ")
	w := bufio.NewReader(os.Stdin)
	otp, err = w.ReadString('\n')
	if err != nil {
		return "", err
	}
	otp = strings.ReplaceAll(strings.TrimSpace(otp), " ", "")
	if otp != "" {
		logs.LOG.WithFields(logrus.Fields{
			"otp": otp,
		}).Trace("Otp provided (interactive)")
	}
	return otp, nil
}
