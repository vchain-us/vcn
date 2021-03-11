/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package sign

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vchain-us/vcn/pkg/meta"
)

// NewUntrustCommand returns the cobra command for `vcn untrust`
func NewUntrustCommand() *cobra.Command {
	cmd := makeCommand()
	cmd.Use = "untrust"
	cmd.Aliases = []string{"ut"}
	cmd.Short = "Untrust an asset"
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		return viper.BindPFlags(cmd.Flags())
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runSignWithState(cmd, args, meta.StatusUntrusted)
	}
	cmd.Long = `
Change an asset's status so it is equal to UNTRUSTED.

Untrust command calculates the SHA-256 hash of a digital asset
(file, directory, container's image).
The hash (not the asset) and the desired status of UNTRUSTED are then
cryptographically signed by the signer's secret (private key).
Next, these signed objects are sent to the blockchain where the signer’s
trust level and a timestamp are added.
When complete, a new blockchain entry is created that binds the asset’s
signed hash, signed status, level, and timestamp together.

Note that your assets will not be uploaded. They will be processed locally.

Assets are referenced by passed ARG(s) with untrust command only accepting
1 ARG at a time.
` + helpMsgFooter
	return cmd
}
