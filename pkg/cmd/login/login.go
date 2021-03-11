/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package login

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"

	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/cli"
	"github.com/vchain-us/vcn/pkg/meta"
	"github.com/vchain-us/vcn/pkg/store"
)

// NewCommand returns the cobra command for `vcn login`
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				return err
			}
			// set port for set up a connection to a CodeNotary Ledger Compliance server (default 443). If --lc-no-tls is provided default port will be 80
			lcPort, err := cmd.Flags().GetString("lc-port")
			if err != nil {
				return err
			}
			noTls, err := cmd.Flags().GetBool("lc-no-tls")
			if err != nil {
				return err
			}
			if noTls && lcPort == "" {
				err = cmd.Flags().Set("lc-port", "80")
				if err != nil {
					return err
				}
			}
			if noTls == false && lcPort == "" {
				err = cmd.Flags().Set("lc-port", "443")
				if err != nil {
					return err
				}
			}
			return nil
		},
		Use:   "login",
		Short: "Log in to codenotary.io or CodeNotary Ledger Compliance",
		Long: `Log in to codenotary.io or CodeNotary Ledger Compliance.

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
		Example: `  # Codenotary.io login:
  ./vcn login
  # CodeNotary Ledger Compliance login:
  ./vcn login --lc-port 33443 --lc-host lc.vchain.us --lc-cert lc.vchain.us
  ./vcn login --lc-port 3324 --lc-host 127.0.0.1 --lc-no-tls
  ./vcn login --lc-port 443 --lc-host lc.vchain.us --lc-cert lc.vchain.us --lc-skip-tls-verify`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			output, err := cmd.Flags().GetString("output")
			if err != nil {
				return err
			}

			lcHost := viper.GetString("lc-host")
			lcPort := viper.GetString("lc-port")
			lcCert := viper.GetString("lc-cert")
			skipTlsVerify := viper.GetBool("lc-skip-tls-verify")
			noTls := viper.GetBool("lc-no-tls")
			lcApiKey := viper.GetString("lc-api-key")

			if lcHost != "" {
				err = ExecuteLC(lcHost, lcPort, lcCert, lcApiKey, skipTlsVerify, noTls)
				if err != nil {
					return err
				}
				if output == "" {
					color.Set(meta.StyleSuccess())
					fmt.Println("Login successful.")
					color.Unset()
				}
				return nil
			}

			if err := Execute(); err != nil {
				return err
			}
			if output == "" {
				fmt.Println("Login successful.")
			}
			return nil
		},
		Args: cobra.MaximumNArgs(2),
	}
	cmd.Flags().String("lc-host", "", meta.VcnLcHostFlagDesc)
	cmd.Flags().String("lc-port", "", meta.VcnLcPortFlagDesc)
	cmd.Flags().String("lc-cert", "", meta.VcnLcCertPathDesc)
	cmd.Flags().Bool("lc-skip-tls-verify", false, meta.VcnLcSkipTlsVerifyDesc)
	cmd.Flags().Bool("lc-no-tls", false, meta.VcnLcNoTlsDesc)
	cmd.Flags().String("lc-api-key", "", meta.VcnLcApiKeyDesc)

	return cmd
}

// Execute the login action
func Execute() error {

	cfg := store.Config()

	email, err := cli.ProvidePlatformUsername()
	if err != nil {
		return err
	}

	user := api.NewUser(email)

	password, err := cli.ProvidePlatformPassword()
	if err != nil {
		return err
	}

	otp, err := cli.ProvideOtp()
	if err != nil {
		return err
	}

	cfg.ClearContext()
	if err := user.Authenticate(password, otp); err != nil {
		return err
	}
	cfg.CurrentContext.Email = user.Email()

	// Store the new config
	if err := store.SaveConfig(); err != nil {
		return err
	}

	api.TrackPublisher(user, meta.VcnLoginEvent)

	return nil
}
