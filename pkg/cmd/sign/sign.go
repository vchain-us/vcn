/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package sign

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vchain-us/vcn/internal/logs"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/vchain-us/vcn/internal/docker"
	"github.com/vchain-us/vcn/internal/utils"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cli"
	"github.com/vchain-us/vcn/pkg/meta"
	"github.com/vchain-us/vcn/pkg/store"
)

// NewCmdSign returns the cobra command for `vcn sign`
func NewCmdSign() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sign",
		Aliases: []string{"s"},
		Short:   "Sign digital assets' hashes onto the blockchain",
		Long:    ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSignWithState(cmd, args, meta.StatusTrusted)
		},

		Args: cobra.ExactArgs(1),
	}

	cmd.Flags().BoolP("public", "p", false, "when signed as public, the asset name and the signer's identity will be visible to everyone")
	cmd.Flags().BoolP("yes", "y", false, "when used, you automatically confirm the ownership of this asset")

	cmd.SetUsageTemplate(
		strings.Replace(cmd.UsageTemplate(), "{{.UseLine}}", "{{.UseLine}} ARG", 1),
	)

	return cmd
}

func runSignWithState(cmd *cobra.Command, args []string, state meta.Status) error {

	public, err := cmd.Flags().GetBool("public")
	if err != nil {
		return err
	}

	yes, err := cmd.Flags().GetBool("yes")
	if err != nil {
		return err
	}

	cmd.SilenceUsage = true
	return sign(args[0], state, meta.VisibilityForFlag(public), yes)
}

func sign(filename string, state meta.Status, visibility meta.Visibility, acknowledge bool) error {

	// check for token
	cli.AssertUserLogin()
	u := api.NewUser(store.Config().CurrentContext)

	// keystore
	cli.AssertUserKeystore()

	var err error
	var artifactHash string
	var fileSize int64

	if strings.HasPrefix(filename, "docker:") {
		artifactHash, err = docker.GetHash(filename)
		if err != nil {
			logs.LOG.Error(err)
			return fmt.Errorf("failed to get hash for docker image")
		}
		fileSize, err = docker.GetSize(filename)
		if err != nil {
			return fmt.Errorf("failed to get size for docker image %s", err)
		}
	} else {
		// file mode
		artifactHash, err = utils.HashFile(filename)
		if err != nil {
			return err
		}
		fi, err := os.Stat(filename)
		if err != nil {
			return err
		}
		fileSize = fi.Size()
	}

	if fileSize < 0 {
		return fmt.Errorf("invalid size")
	}
	size := uint64(fileSize)

	reader := bufio.NewReader(os.Stdin)

	if !acknowledge {
		fmt.Println("CodeNotary - code signing in 1 simple step:")
		fmt.Println()
		fmt.Println("Attention, by signing this asset with CodeNotary you implicitly claim its ownership.")
		fmt.Println("Doing this can potentially infringe other publisher's intellectual property under the laws of your country of residence.")
		fmt.Println("vChain and the Zero Trust Consortium cannot be held responsible for legal ramifications.")
		color.Set(color.FgGreen)
		fmt.Println()
		fmt.Println("If you are the owner of the asset (e.g. author, creator, publisher) you can continue")
		color.Unset()
		fmt.Println()
		fmt.Print("I understand and want to continue. (y/n)")
		question, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(question)) != "y" {
			os.Exit(1)
		}
	}

	passphrase, err := cli.ProvidePassphrase()
	if err != nil {
		return err
	}

	s := spinner.New(spinner.CharSets[1], 500*time.Millisecond)

	s.Prefix = "Signing asset... "
	s.Start()

	name := filepath.Base(filename)
	a := api.Artifact{
		Name: name,
		Hash: artifactHash,
		Size: size,
	}

	// TODO: return and display: block #, trx #
	err = u.Sign(a, u.DefaultKey(), passphrase, state, visibility)

	s.Stop()
	if err != nil {
		return err
	}

	fmt.Println("")
	fmt.Println("Asset:\t", filename)
	fmt.Println("Hash:\t", artifactHash)
	// fmt.Println("Date:\t\t", time.Now())
	// fmt.Println("Signer:\t", "<pubKey>")
	return nil
}
