/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package verify

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/fatih/color"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/cli"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
	"github.com/vchain-us/vcn/pkg/extractor"
	"github.com/vchain-us/vcn/pkg/meta"
	"github.com/vchain-us/vcn/pkg/store"
)

var (
	keyRegExp = regexp.MustCompile("0x[0-9a-z]{40}")
)

func getSignerIDs() []string {
	ids := viper.GetStringSlice("signerID")
	if len(ids) > 0 {
		return ids
	}
	return viper.GetStringSlice("key")
}

// NewCommand returns the cobra command for `vcn verify`
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "authenticate",
		Example: "  vcn authenticate /bin/vcn",
		Aliases: []string{"a", "verify", "v"},
		Short:   "Authenticate assets against the blockchain",
		Long: `
Authenticate assets against the blockchain.

Authentication is the process of matching the hash of a local asset to
a hash on the blockchain.
If matched, the returned result (the authentication) is the blockchain-stored
metadata that’s bound to the matching hash.
Otherwise, the returned result status equals UNKNOWN.

Note that your assets will not be uploaded but processed locally.

The exit code will be 0 only if all assets' statuses are equal to TRUSTED.
Otherwise, the exit code will be 1.

Assets are referenced by the passed ARG(s), with authentication accepting
1 or more ARG(s) at a time. Multiple assets can be authenticated at the
same time while passing them within ARG(s).

ARG must be one of:
  <file>
  file://<file>
  dir://<directory>
  git://<repository>
  docker://<image>
  podman://<image>

Environment variables:
VCN_USER=
VCN_PASSWORD=
VCN_NOTARIZATION_PASSWORD=
VCN_NOTARIZATION_PASSWORD_EMPTY=
VCN_OTP=
VCN_OTP_EMPTY=
VCN_LC_HOST=
VCN_LC_PORT=
VCN_LC_CERT=
VCN_LC_SKIP_TLS_VERIFY=false
VCN_LC_NO_TLS=false
VCN_LC_API_KEY=
`,
		RunE: runVerify,
		PreRun: func(cmd *cobra.Command, args []string) {
			// Bind to all flags to env vars (after flags were parsed),
			// but only ones retrivied by using viper will be used.
			viper.BindPFlags(cmd.Flags())
		},
		Args: func(cmd *cobra.Command, args []string) error {
			if org := viper.GetString("org"); org != "" {
				if keys := getSignerIDs(); len(keys) > 0 {
					return fmt.Errorf("cannot use both --org and SignerID(s)")
				}
			}

			alerts, _ := cmd.Flags().GetBool("alerts")
			if alerts {
				if len(args) > 0 {
					return fmt.Errorf("cannot use ARG(s) with --alerts")
				}
				return nil
			}

			if hash, _ := cmd.Flags().GetString("hash"); hash != "" {
				if len(args) > 0 {
					return fmt.Errorf("cannot use ARG(s) with --hash")
				}
				if alerts {
					return fmt.Errorf("cannot use both --alerts and --hash")
				}

				return nil
			}
			return cobra.MinimumNArgs(1)(cmd, args)
		},
	}

	cmd.SetUsageTemplate(
		strings.Replace(cmd.UsageTemplate(), "{{.UseLine}}", "{{.UseLine}} ARG(s)", 1),
	)

	cmd.Flags().StringSliceP("signerID", "s", nil, "accept only authentications matching the passed SignerID(s)\n(overrides VCN_SIGNERID env var, if any). It's valid both for blockchain and ledger compliance")
	cmd.Flags().StringSliceP("key", "k", nil, "")
	cmd.Flags().MarkDeprecated("key", "please use --signerID instead")
	cmd.Flags().StringP("org", "I", "", "accept only authentications matching the passed organisation's ID,\nif set no SignerID can be used\n(overrides VCN_ORG env var, if any)")
	cmd.Flags().String("hash", "", "specify a hash to authenticate, if set no ARG(s) can be used")
	cmd.Flags().Bool("alerts", false, "specify to authenticate and monitor for the configured alerts, if set no ARG(s) can be used")
	cmd.Flags().Bool("raw-diff", false, "print raw a diff, if any")
	cmd.Flags().Int("exit-code", meta.VcnDefaultExitCode, meta.VcnExitCode)
	cmd.Flags().String("lc-host", "", meta.VcnLcHostFlagDesc)
	cmd.Flags().String("lc-port", "443", meta.VcnLcPortFlagDesc)
	cmd.Flags().String("lc-cert", "", meta.VcnLcCertPathDesc)
	cmd.Flags().Bool("lc-skip-tls-verify", false, meta.VcnLcSkipTlsVerifyDesc)
	cmd.Flags().Bool("lc-no-tls", false, meta.VcnLcNoTlsDesc)
	cmd.Flags().String("lc-api-key", "", meta.VcnLcApiKeyDesc)

	cmd.Flags().MarkHidden("raw-diff")

	return cmd
}

// runVerify first determine if the context is LC or blockchain, then call the correct verify
func runVerify(cmd *cobra.Command, args []string) error {
	hash, err := cmd.Flags().GetString("hash")
	if err != nil {
		return err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	useAlerts, err := cmd.Flags().GetBool("alerts")
	if err != nil {
		return err
	}

	cmd.SilenceUsage = true

	lcHost := viper.GetString("lc-host")
	lcPort := viper.GetString("lc-port")
	lcCert := viper.GetString("lc-cert")
	skipTlsVerify := viper.GetBool("lc-skip-tls-verify")
	noTls := viper.GetBool("lc-no-tls")
	lcApiKey := viper.GetString("lc-api-key")
	//check if an lcUser is present inside the context
	var lcUser *api.LcUser
	uif, err := api.GetUserFromContext(store.Config().CurrentContext, lcApiKey)
	if err != nil {
		return err
	}
	if lctmp, ok := uif.(*api.LcUser); ok {
		lcUser = lctmp
	}

	// use credentials if host is at least host is provided
	if lcHost != "" && lcApiKey != "" {
		lcUser, err = api.NewLcUser(lcApiKey, lcHost, lcPort, lcCert, skipTlsVerify, noTls)
		if err != nil {
			return err
		}
		// Store the new config
		if err := store.SaveConfig(); err != nil {
			return err
		}
	}

	if lcUser != nil {
		var signerID string
		signerIDs := getSignerIDs()
		if len(signerIDs) > 0 {
			signerID = signerIDs[0]
		}
		err = lcUser.Client.Connect()
		if err != nil {
			return err
		}
		// by hash
		if hash != "" {
			a := &api.Artifact{
				Hash: strings.ToLower(hash),
			}
			return lcVerify(cmd, a, lcUser, signerID, output)
		}

		artifacts, err := extractor.Extract([]string{args[0]})
		if err != nil {
			return err
		}
		for _, a := range artifacts {
			err := lcVerify(cmd, a, lcUser, signerID, output)
			if err != nil {
				return err
			}
		}
		return nil
	}

	// blockchain context
	org := viper.GetString("org")
	var keys []string
	if org != "" {
		bo, err := api.GetBlockChainOrganisation(org)
		if err != nil {
			return err
		}
		keys = bo.MembersIDs()
	} else {
		keys = getSignerIDs()
		// add 0x if missing, lower case, and check if format is correct
		for i, k := range keys {
			if !strings.HasPrefix(k, "0x") {
				keys[i] = "0x" + k
			}
			keys[i] = strings.ToLower(keys[i])
			if !keyRegExp.MatchString(keys[i]) {
				return fmt.Errorf("invalid public address format: %s", k)
			}
		}
	}

	user := api.NewUser(store.Config().CurrentContext.Email)

	// by alerts
	if useAlerts {
		if hasAuth, _ := user.IsAuthenticated(); !hasAuth {
			return fmt.Errorf("in order to use --alerts, you need to be logged in\nProceed by authenticating yourself using <vcn login>")
		}

		alertConfigPath, err := store.AlertFilepath(user.Email())
		if err != nil {
			return err
		}
		if output == "" {
			fmt.Printf("Using alert configuration: %s\n\n", alertConfigPath)
		}

		alerts, err := store.ReadAlerts(user.Email())
		if err != nil {
			return err
		}

		if len(alerts) == 0 {
			return fmt.Errorf("no configured alerts")
		}

		for _, alert := range alerts {
			var alertConfig api.AlertConfig
			if err := alert.ExportConfig(&alertConfig); err != nil {
				cli.PrintWarning(output, fmt.Sprintf(
					`invalid alert config (name="%s") for %s: %s`,
					alert.Name,
					alert.Arg,
					err,
				))
				continue
			}
			alertConfig.Metadata["arg"] = alert.Arg

			artifacts, err := extractor.Extract([]string{alert.Arg})
			if err != nil {
				cli.PrintWarning(output, err.Error())
				alertConfig.Metadata["error"] = err.Error()
				user.TriggerAlert(alertConfig)
				continue
			}
			if artifacts == nil {
				cli.PrintWarning(output, fmt.Sprintf("unable to process the input asset provided: %s", alert.Arg))
				alertConfig.Metadata["error"] = err.Error()
				user.TriggerAlert(alertConfig)
				continue
			}
			for _, a := range artifacts {
				if err := verify(cmd, a, keys, org, user, &alertConfig, output); err != nil {
					cli.PrintWarning(output, fmt.Sprintf("%s: %s", alert.Arg, err))
				}
				if output == "" {
					fmt.Println()
				}
			}
		}
		return nil
	}

	// by hash
	if hash != "" {
		a := &api.Artifact{
			Hash: strings.ToLower(hash),
		}
		if err := verify(cmd, a, keys, org, user, nil, output); err != nil {
			return err
		}
		return nil
	}

	// by args
	for _, arg := range args {
		artifacts, err := extractor.Extract([]string{arg})
		if err != nil {
			return err
		}
		if artifacts == nil {
			return fmt.Errorf("unable to process the input asset provided: %s", arg)
		}
		for _, a := range artifacts {
			if err := verify(cmd, a, keys, org, user, nil, output); err != nil {
				return err
			}
		}
	}

	return nil
}

func verify(cmd *cobra.Command, a *api.Artifact, keys []string, org string, user *api.User, alertConfig *api.AlertConfig, output string) (err error) {
	hook := newHook(cmd, a)
	var verification *api.BlockchainVerification
	if output == "" {
		fmt.Println()
		color.Set(meta.StyleAffordance())
		fmt.Println("Your assets will not be uploaded. They will be processed locally.")
		color.Unset()
		fmt.Println()
	}
	// if keys have been passed, check for a verification matching them
	if len(keys) > 0 {
		if output == "" {
			if org == "" {
				fmt.Printf("Looking for blockchain entry matching the passed SignerIDs...\n")
			} else {
				fmt.Printf("Looking for blockchain entry matching the organization (%s)...\n", org)
			}
		}
		verification, err = api.VerifyMatchingSignerIDs(a.Hash, keys)

	} else {
		// if we have an user, check for verification matching user's key first
		userKey := ""
		if hasAuth, _ := user.IsAuthenticated(); hasAuth {
			userKey, _ = user.SignerID() // todo(leogr): double check this
		}
		if userKey != "" {
			if output == "" {
				fmt.Printf("Looking for blockchain entry matching the current user (%s)...\n", user.Email())
			}
			verification, err = api.VerifyMatchingSignerIDWithFallback(a.Hash, userKey)
			if output == "" {
				if verification.SignerID() != userKey {
					fmt.Printf("No blockchain entry matching the current user found.\n")
					if !verification.Unknown() {
						fmt.Printf("Showing the last blockchain entry with highest level available.\n")
					}
				}
			}
		} else {
			// if no passed keys nor user,
			// just get the last with highest level available verification
			if output == "" {
				fmt.Printf("Looking for the last blockchain entry with highest level available...\n")
			}
			verification, err = api.Verify(a.Hash)
		}
	}

	if output == "" {
		fmt.Println()
	}

	if err != nil {
		return fmt.Errorf("unable to authenticate the hash: %s", err)
	}

	err = hook.finalize(alertConfig, output)
	if err != nil {
		return err
	}

	var ar *api.ArtifactResponse
	if !verification.Unknown() {
		ar, _ = api.LoadArtifact(user, a.Hash, verification.MetaHash())
	}

	if err = cli.Print(output, types.NewResult(a, ar, verification)); err != nil {
		return err
	}

	if output != "" {
		cmd.SilenceErrors = true
	}

	// todo(ameingast/leogr): remove reduntat event - need backend improvement
	if verification.Trusted() {
		api.TrackVerify(user, a.Hash, a.Name)
	}

	if alertConfig != nil {
		var err error
		if verification.Trusted() {
			err = user.PingAlert(*alertConfig)
		} else {
			err = user.TriggerAlert(*alertConfig)
		}
		if err != nil {
			return err
		}

		if output == "" {
			fmt.Printf("\nPing for alert %s sent.\n", alertConfig.AlertUUID)
		}
		api.TrackPublisher(user, meta.VcnAlertVerifyEvent)
	} else {
		api.TrackPublisher(user, meta.VcnVerifyEvent)
	}

	if !verification.Trusted() {
		errLabels := map[meta.Status]string{
			meta.StatusUnknown:     "was not notarized",
			meta.StatusUntrusted:   "is untrusted",
			meta.StatusUnsupported: "is unsupported",
		}

		switch true {
		case org != "":
			return fmt.Errorf(`%s %s by "%s"`, a.Hash, errLabels[verification.Status], org)
		case len(keys) == 1:
			return fmt.Errorf("%s %s by %s", a.Hash, errLabels[verification.Status], keys[0])
		case len(keys) > 1:
			return fmt.Errorf("%s %s by any of %s", a.Hash, errLabels[verification.Status], strings.Join(keys, ", "))
		default:
			return fmt.Errorf("%s %s", a.Hash, errLabels[verification.Status])
		}
	}

	return
}
