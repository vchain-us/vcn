/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package inspect

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/vchain-us/vcn/internal/assert"
	"github.com/vchain-us/vcn/pkg/meta"
	"strings"

	"github.com/vchain-us/vcn/pkg/cmd/internal/cli"

	"github.com/spf13/cobra"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
	"github.com/vchain-us/vcn/pkg/extractor"
	"github.com/vchain-us/vcn/pkg/store"
)

// NewCommand returns the cobra command for `vcn inspect`
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"i"},
		Short:   "Returns the asset history with low-level information",
		Long: `
Returns the asset history with low-level information

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
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		RunE: runInspect,
		Args: func(cmd *cobra.Command, args []string) error {
			if hash, _ := cmd.Flags().GetString("hash"); hash != "" {
				if len(args) > 0 {
					return fmt.Errorf("cannot use ARG(s) with --hash")
				}
				return nil
			}

			first, _ := cmd.Flags().GetUint64("first")
			last, _ := cmd.Flags().GetUint64("last")
			start, _ := cmd.Flags().GetString("start")
			end, _ := cmd.Flags().GetString("end")

			if (first > 0 || last > 0 || start != "" || end != "") &&
				store.Config().CurrentContext.LcHost == "" {
				return fmt.Errorf("time range filter is available only in Ledger Compliance environment")
			}

			if first > 0 && last > 0 {
				return fmt.Errorf("--first and --last are mutual exclusive")
			}
			return cobra.MinimumNArgs(1)(cmd, args)
		},
		Example: `
vcn inspect document.pdf --last 1
vcn inspect document.pdf --first 1
vcn inspect document.pdf --start 2020/10/28-08:00:00 --end 2020/10/28-17:00:00 --first 10
vcn inspect document.pdf --signerID CygBE_zb8XnprkkO6ncIrbbwYoUq5T1zfyEF6DhqcAI= --start 2020/10/28-16:00:00 --end 2020/10/28-17:10:00 --last 3
`,
	}

	cmd.SetUsageTemplate(
		strings.Replace(cmd.UsageTemplate(), "{{.UseLine}}", "{{.UseLine}} ARG", 1),
	)

	cmd.Flags().String("hash", "", "specify a hash to inspect, if set no ARG can be used")
	cmd.Flags().Bool("extract-only", false, "if set, print only locally extracted info")
	// ledger compliance flags
	cmd.Flags().String("lc-host", "", meta.VcnLcHostFlagDesc)
	cmd.Flags().String("lc-port", "443", meta.VcnLcPortFlagDesc)
	cmd.Flags().String("lc-cert", "", meta.VcnLcCertPathDesc)
	cmd.Flags().Bool("lc-skip-tls-verify", false, meta.VcnLcSkipTlsVerifyDesc)
	cmd.Flags().Bool("lc-no-tls", false, meta.VcnLcNoTlsDesc)
	cmd.Flags().String("lc-api-key", "", meta.VcnLcApiKeyDesc)

	cmd.Flags().String("signerID", "", "specify a signerID to refine inspection result on ledger compliance")

	cmd.Flags().Uint64("first", 0, "set the limit for the first elements filter")
	cmd.Flags().Uint64("last", 0, "set the limit for the last elements filter")

	cmd.Flags().String("start", "", "set the start of date and time range filter. Example 2020/10/28-16:00:00")
	cmd.Flags().String("end", "", "set the end of date and time range filter. Example 2020/10/28-16:00:00")

	return cmd
}

func runInspect(cmd *cobra.Command, args []string) error {

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	hash, err := cmd.Flags().GetString("hash")
	if err != nil {
		return err
	}
	hash = strings.ToLower(hash)

	extractOnly, err := cmd.Flags().GetBool("extract-only")
	if err != nil {
		return err
	}
	cmd.SilenceUsage = true

	if hash == "" {
		if len(args) < 1 {
			return fmt.Errorf("no argument")
		}
		if hash, err = extractInfo(args[0], output); err != nil {
			return err
		}
		if output == "" {
			fmt.Print("\n\n")
		}
	}

	if extractOnly {
		return nil
	}

	signerID, err := cmd.Flags().GetString("signerID")
	if err != nil {
		return err
	}

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
		} // Store the new config
		if err := store.SaveConfig(); err != nil {
			return err
		}
	}

	if lcUser != nil {
		err = lcUser.Client.Connect()
		if err != nil {
			return err
		}
		first, err := cmd.Flags().GetUint64("first")
		if err != nil {
			return err
		}
		last, err := cmd.Flags().GetUint64("last")
		if err != nil {
			return err
		}
		start, err := cmd.Flags().GetString("start")
		if err != nil {
			return err
		}
		end, err := cmd.Flags().GetString("end")
		if err != nil {
			return err
		}

		if first == 0 && last == 0 {
			last = 100
			fmt.Printf("no filter is specified. At maximum last 100 items will be returned\n")
		}
		return lcInspect(hash, signerID, lcUser, first, last, start, end, output)
	}

	// User
	if err := assert.UserLogin(); err != nil {
		return err
	}
	u, ok := uif.(*api.User)
	if !ok {
		return fmt.Errorf("cannot load the current user")
	}

	if hasAuth, _ := u.IsAuthenticated(); hasAuth && output == "" {
		fmt.Printf("Current user: %s\n", u.Email())
	}

	return inspect(hash, u, output)
}

func extractInfo(arg string, output string) (hash string, err error) {
	a, err := extractor.Extract(arg)
	if err != nil {
		return "", err
	}
	if len(a) == 0 {
		return "", fmt.Errorf("unable to process the input asset provided: %s", arg)
	}
	if len(a) == 1 {
		hash = a[0].Hash
	}
	if len(a) > 1 {
		return "", fmt.Errorf("info extraction on multiple items is not yet supported")
	}
	if output == "" {
		fmt.Printf("Extracted info from: %s\n\n", arg)
	}
	cli.Print(output, types.NewResult(a[0], nil, nil))
	return
}

func inspect(hash string, u *api.User, output string) error {
	results, err := GetResults(hash, u)
	if err != nil {
		return err
	}

	if output == "" {
		fmt.Printf(
			`%d notarizations found for "%s"

`,
			len(results), hash)
	}

	return cli.PrintSlice(output, results)
}

func GetResults(hash string, u *api.User) ([]types.Result, error) {
	verifications, err := api.BlockChainInspect(hash)
	if err != nil {
		return nil, err
	}
	l := len(verifications)

	results := make([]types.Result, l)
	for i, v := range verifications {
		ar, err := api.LoadArtifact(u, hash, v.MetaHash())
		results[i] = *types.NewResult(nil, ar, &v)
		if err != nil {
			results[i].AddError(err)
		}
		// check if artifact is synced, if any
		if ar != nil {
			if v.Status.String() != ar.Status {
				results[i].AddError(fmt.Errorf(
					"status not in sync (blockchain: %s, platform: %s)", v.Status.String(), ar.Status,
				))
			}
			if int64(v.Level) != ar.Level {
				results[i].AddError(fmt.Errorf(
					"level not in sync (blockchain: %d, platform: %d)", v.Level, ar.Level,
				))
			}
		}
	}
	return results, nil
}
