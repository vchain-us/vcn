/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package sign

import (
	"bufio"
	"fmt"
	"github.com/spf13/viper"
	"github.com/vchain-us/vcn/pkg/extractor/wildcard"
	"os"
	"strings"

	"github.com/vchain-us/vcn/pkg/extractor/dir"

	"github.com/fatih/color"

	"github.com/caarlos0/spin"
	"github.com/spf13/cobra"
	"github.com/vchain-us/vcn/internal/assert"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/cli"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
	"github.com/vchain-us/vcn/pkg/extractor"
	"github.com/vchain-us/vcn/pkg/meta"
	"github.com/vchain-us/vcn/pkg/store"
)

const longDescFooter = `

VCN_NOTARIZATION_PASSWORD env var can be used to pass the
required notarization password in a non-interactive environment.
`

const helpMsgFooter = `
ARG must be one of:
  wildcard
  file://<file>
  dir://<directory>
  git://<repository>
  docker://<image>
  podman://<image>
  wildcard://"*"
`

// NewCommand returns the cobra command for `vcn sign`
func NewCommand() *cobra.Command {
	cmd := makeCommand()
	cmd.Flags().Bool("create-alert", false, "if set, an alert will be created (config will be stored into the .vcn dir)")
	cmd.Flags().String("alert-name", "", "set the alert name (ignored if --create-alert is not set)")
	cmd.Flags().String("alert-email", "", "set the alert email recipient (ignored if --create-alert is not set)")
	return cmd
}

func makeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "notarize",
		Aliases: []string{"n", "sign", "s"},
		Short:   "Notarize an asset onto the blockchain",
		Long: `
Notarize an asset onto the blockchain.

Notarization calculates the SHA-256 hash of a digital asset
(file, directory, container's image).
The hash (not the asset) and the desired status of TRUSTED are then
cryptographically signed by the signer's secret (private key).
Next, these signed objects are sent to the blockchain where the signer’s
trust level and a timestamp are added.
When complete, a new blockchain entry is created that binds the asset’s
signed hash, signed status, level, and timestamp together.

Note that your assets will not be uploaded. They will be processed locally.

Assets are referenced by passed ARG with notarization only accepting
1 ARG at a time.

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

` + helpMsgFooter,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if pipeMode() {
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Split(bufio.ScanWords)
				for scanner.Scan() {
					token := scanner.Bytes()
					args = append(args, string(token))
				}
				if err := scanner.Err(); err != nil {
					fmt.Errorf("error parsing stdin input: %s", err)
				}
			}
			return runSignWithState(cmd, args, meta.StatusTrusted)
		},
		Args: noArgsWhenHashOrPipe,
		Example: `vcn notarize my-file"
vcn notarize -r "*.md"
echo my-file | vcn n`,
	}

	cmd.Flags().VarP(make(mapOpts), "attr", "a", "add user defined attributes (repeat --attr for multiple entries)")
	cmd.Flags().StringP("name", "n", "", "set the asset name")
	cmd.Flags().BoolP("public", "p", false, "when notarized as public, the asset name and metadata will be visible to everyone")
	cmd.Flags().String("hash", "", "specify the hash instead of using an asset, if set no ARG(s) can be used")
	cmd.Flags().Bool("no-ignore-file", false, "if set, .vcnignore will be not written inside the targeted dir (affects dir:// only)")
	cmd.Flags().Bool("read-only", false, "if set, no files will be written into the targeted dir (affects dir:// only)")
	cmd.Flags().BoolP("recursive", "r", false, "if set, wildcard usage will walk inside subdirectories of provided path")
	cmd.Flags().String("lc-host", "", meta.VcnLcHostFlagDesc)
	cmd.Flags().String("lc-port", "443", meta.VcnLcPortFlagDesc)
	cmd.Flags().String("lc-cert", "", meta.VcnLcCertPathDesc)
	cmd.Flags().Bool("lc-skip-tls-verify", false, meta.VcnLcSkipTlsVerifyDesc)
	cmd.Flags().Bool("lc-no-tls", false, meta.VcnLcNoTlsDesc)
	cmd.Flags().String("lc-api-key", "", meta.VcnLcApiKeyDesc)
	cmd.SetUsageTemplate(
		strings.Replace(cmd.UsageTemplate(), "{{.UseLine}}", "{{.UseLine}} ARG", 1),
	)

	return cmd
}

func runSignWithState(cmd *cobra.Command, args []string, state meta.Status) error {
	// default extractors options
	extractorOptions := []extractor.Option{}

	noIgnoreFile, err := cmd.Flags().GetBool("no-ignore-file")
	if err != nil {
		return err
	}
	readOnly, err := cmd.Flags().GetBool("read-only")
	if err != nil {
		return err
	}
	if readOnly {
		noIgnoreFile = true
	}
	if !noIgnoreFile {
		extractorOptions = append(extractorOptions, dir.WithIgnoreFileInit())
		extractorOptions = append(extractorOptions, dir.WithSkipIgnoreFileErr())
	}

	recursive, err := cmd.Flags().GetBool("recursive")
	if err != nil {
		return err
	}
	if recursive {
		extractorOptions = append(extractorOptions, wildcard.WithRecursive())
	}
	var alert *alertOptions
	if hasCreateAlert := cmd.Flags().Lookup("create-alert"); hasCreateAlert != nil {
		createAlert, err := cmd.Flags().GetBool("create-alert")
		if err != nil {
			return err
		}
		if createAlert {
			alert = &alertOptions{
				arg: args[0],
			}
			alert.name, _ = cmd.Flags().GetString("alert-name")
			if err != nil {
				return err
			}
			alert.email, _ = cmd.Flags().GetString("alert-email")
			if err != nil {
				return err
			}
		}
	}

	var hash string
	if hashFlag := cmd.Flags().Lookup("hash"); hashFlag != nil {
		var err error
		hash, err = cmd.Flags().GetString("hash")
		if err != nil {
			return err
		}
	}

	public, err := cmd.Flags().GetBool("public")
	if err != nil {
		return err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	silentMode, err := cmd.Flags().GetBool("silent")
	if err != nil {
		return err
	}

	name, err := cmd.Flags().GetString("name")
	if err != nil {
		return err
	}

	metadata := cmd.Flags().Lookup("attr").Value.(mapOpts).StringToInterface()

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

	// use credentials if at least ledger compliance host is provided
	if lcHost != "" && lcApiKey != "" {
		lcUser, err = api.NewLcUser(lcApiKey, lcHost, lcPort, lcCert, skipTlsVerify, noTls)
		if err != nil {
			return err
		} // Store the new config
		if err := store.SaveConfig(); err != nil {
			return err
		}
	}

	var artifacts []*api.Artifact

	if lcUser != nil {
		err = lcUser.Client.Connect()
		if err != nil {
			return err
		}
		if hash != "" {
			hash = strings.ToLower(hash)
			// Load existing artifact, if any, otherwise use an empty artifact
			if ar, _, err := lcUser.LoadArtifact(hash, "", 0); err == nil && ar != nil {
				artifacts = []*api.Artifact{{
					Kind:        ar.Kind,
					Name:        ar.Name,
					Hash:        ar.Hash,
					Size:        ar.Size,
					ContentType: ar.ContentType,
					Metadata:    ar.Metadata,
				}}
			} else {
				if name == "" {
					return fmt.Errorf("please set an asset name, by using --name")
				}
				artifacts = []*api.Artifact{{Hash: hash}}
			}
		} else {
			artifacts, err = extractor.Extract(args, extractorOptions...)
			if err != nil {
				return err
			}
		}
		return LcSign(lcUser, artifacts, state, output, name, metadata)
	}

	// User
	if err := assert.UserLogin(); err != nil {
		return err
	}
	u, ok := uif.(*api.User)
	if !ok {
		return fmt.Errorf("cannot load the current user")
	}

	// Make the artifact to be signed

	if hash != "" {
		if alert != nil {
			return fmt.Errorf("cannot use --create-alert with --hash")
		}
		hash = strings.ToLower(hash)
		// Load existing artifact, if any, otherwise use an empty artifact
		if ar, err := u.LoadArtifact(hash); err == nil && ar != nil {
			artifacts = []*api.Artifact{ar.Artifact()}
		} else {
			if name == "" {
				return fmt.Errorf("please set an asset name, by using --name")
			}
			artifacts = []*api.Artifact{{Hash: hash}}
		}
	} else {
		// Extract artifact from arg
		artifacts, err = extractor.Extract(args, extractorOptions...)
		if err != nil {
			return err
		}
	}

	if artifacts == nil {
		return fmt.Errorf("unable to process the input asset provided")
	}

	if len(artifacts) == 1 {
		// Override the asset's name, if provided by --name
		if name != "" {
			artifacts[0].Name = name
		}
	}

	for _, a := range artifacts {
		// Copy user provided custom attributes
		a.Metadata.SetValues(metadata)

		err := sign(*u, *a, state, meta.VisibilityForFlag(public), output, silentMode, readOnly, alert)
		if err != nil {
			return err
		}
	}

	return nil
}

func sign(u api.User, a api.Artifact, state meta.Status, visibility meta.Visibility, output string, silent bool, readOnly bool, alert *alertOptions) error {

	if output == "" {
		color.Set(meta.StyleAffordance())
		fmt.Print("Your assets will not be uploaded. They will be processed locally.")
		color.Unset()
		fmt.Println()
		fmt.Println()
		fmt.Println("Signer:\t" + u.Email())
	}

	hook := newHook(&a)

	s := spin.New("%s Notarization in progress...")
	s.Set(spin.Spin1)

	var verification *api.BlockchainVerification
	var err error

	for i := 1; true; i++ {
		var passphrase string
		var interactive bool
		passphrase, interactive, err = cli.ProvidePassphrase()
		if err != nil {
			return err
		}

		if output == "" && !silent {
			s.Start()
		}

		var keyin string
		var offline bool
		keyin, _, offline, err = u.Secret()
		if err != nil {
			return err
		}
		if offline {
			return fmt.Errorf("offline secret is not supported by the current vcn version")
		}

		verification, err = u.Sign(
			a,
			api.SignWithStatus(state),
			api.SignWithVisibility(visibility),
			api.SignWithKey(keyin, passphrase),
		)

		if err != nil && i >= 3 {
			s.Stop()
			return fmt.Errorf("too many failed attempts: %s", err)
		}

		if interactive && err == api.WrongPassphraseErr {
			s.Stop()
			fmt.Printf("\nError: %s, please try again\n\n", err.Error())
			continue
		}
		break
	}

	s.Stop()

	if err != nil {
		return err
	}

	// once transaction is confirmed we don't want to show errors, just print warnings instead.

	// todo(ameingast/leogr): remove redundant event - need backend improvement
	api.TrackPublisher(&u, meta.VcnSignEvent)
	api.TrackSign(&u, a.Hash, a.Name, state)

	err = hook.finalize(verification, readOnly)
	if err != nil {
		return cli.PrintWarning(output, err.Error())
	}

	if output == "" {
		fmt.Println()
	}

	artifact, err := api.LoadArtifact(&u, a.Hash, verification.MetaHash())
	if err != nil {
		return cli.PrintWarning(output, err.Error())
	}

	cli.Print(output, types.NewResult(&a, artifact, verification))

	if err := handleAlert(alert, u, a, *verification, output); err != nil {
		return cli.PrintWarning(output, err.Error())
	}

	return nil
}

func pipeMode() bool {
	fileInfo, _ := os.Stdin.Stat()
	return fileInfo.Mode()&os.ModeCharDevice == 0
}
