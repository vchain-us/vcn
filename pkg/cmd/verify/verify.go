/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package verify

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/cli"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
	"github.com/vchain-us/vcn/pkg/extractor"
	"github.com/vchain-us/vcn/pkg/meta"
	"github.com/vchain-us/vcn/pkg/store"
)

// NewCmdVerify returns the cobra command for `vcn verify`
func NewCmdVerify() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "verify",
		Example: "  vcn verify /bin/vcn",
		Aliases: []string{"v"},
		Short:   "Verify digital artifact against blockchain",
		Long:    ``,
		RunE:    runVerify,
		Args: func(cmd *cobra.Command, args []string) error {
			if org := viper.GetString("verify_org"); org != "" {
				if keys := viper.GetStringSlice("verify_keys"); len(keys) > 0 {
					return fmt.Errorf("cannot use both --org and other key(s)")
				}
			}

			if hash, _ := cmd.Flags().GetString("hash"); hash != "" {
				if len(args) > 0 {
					return fmt.Errorf("cannot use arg(s) with --hash")
				}
				return nil
			}
			return cobra.MinimumNArgs(1)(cmd, args)
		},
	}

	cmd.SetUsageTemplate(
		strings.Replace(cmd.UsageTemplate(), "{{.UseLine}}", "{{.UseLine}} ...ARG(s)", 1),
	)

	cmd.Flags().StringSliceP("key", "k", nil, "accept only verification matching the passed key(s)")
	cmd.Flags().String("org", "", "accept only verification matching the passed organisation's ID, if set no other key(s) can be used")
	cmd.Flags().String("hash", "", "specify a hash to verify, if set no arg(s) can be used")

	// Bind to VCN_VERIFY_KEYS and VCN_VERIFY_ORG env vars
	viper.BindPFlag("verify_keys", cmd.Flags().Lookup("key"))
	viper.BindPFlag("verify_org", cmd.Flags().Lookup("org"))

	return cmd
}

func runVerify(cmd *cobra.Command, args []string) error {
	hash, err := cmd.Flags().GetString("hash")
	if err != nil {
		return err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	cmd.SilenceUsage = true

	org := viper.GetString("verify_org")
	var keys []string
	if org != "" {
		bo, err := api.BlockChainGetOrganisation(org)
		if err != nil {
			return err
		}
		keys = bo.MembersKeys()
	} else {
		keys = viper.GetStringSlice("verify_keys")
	}

	user := api.NewUser(store.Config().CurrentContext)

	// by hash
	if hash != "" {
		a := &api.Artifact{
			Hash: hash,
		}
		if err := verify(cmd, a, keys, org, user, output); err != nil {
			return err
		}
		return nil
	}

	// else by args
	for _, arg := range args {
		a, err := extractor.Extract(arg)
		if err != nil {
			return err
		}
		if err := verify(cmd, a, keys, org, user, output); err != nil {
			return err
		}
	}

	return nil
}

func verify(cmd *cobra.Command, a *api.Artifact, keys []string, org string, user *api.User, output string) (err error) {
	var verification *api.BlockchainVerification
	// if keys have been passed, check for a verification matching them
	if len(keys) > 0 {
		verification, err = api.BlockChainVerifyMatchingPublicKeys(a.Hash, keys)
	} else {
		// if we have an user, check for verification matching user's keys first
		if hasAuth, _ := user.IsAuthenticated(); hasAuth {
			if userKeys := user.Keys(); len(userKeys) > 0 {
				verification, err = api.BlockChainVerifyMatchingPublicKeys(a.Hash, userKeys)
			}
		}
		// if no user nor verification matching the user has found,
		// fallback to the last with highest level avaiable verification
		if verification.Unknown() {
			verification, err = api.BlockChainVerify(a.Hash)
		}
	}

	if err != nil {
		return fmt.Errorf("unable to verify hash: %s", err)
	}

	var ar *api.ArtifactResponse
	if !verification.Unknown() {
		ar, _ = api.LoadArtifactForHash(user, a.Hash, verification.MetaHash())
	}

	if err = cli.Print(output, types.NewResult(a, ar, verification)); err != nil {
		return err
	}

	if output != "" {
		cmd.SilenceErrors = true
	}

	// todo(ameingast): redundant tracking events?
	_ = api.TrackPublisher(user, meta.VcnVerifyEvent)
	_ = api.TrackVerify(user, a.Hash, a.Name)

	if !verification.Trusted() {
		switch true {
		case org != "":
			return fmt.Errorf(`%s is not verified by "%s"`, a.Hash, org)
		case len(keys) == 1:
			return fmt.Errorf("%s is not verified by %s", a.Hash, keys[0])
		case len(keys) > 1:
			return fmt.Errorf("%s is not verified by any of %s", a.Hash, strings.Join(keys, ", "))
		default:
			return fmt.Errorf("%s is not verified", a.Hash)
		}
	}

	return
}
