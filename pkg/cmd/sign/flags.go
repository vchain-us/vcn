/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package sign

import (
	"fmt"

	"github.com/spf13/cobra"
)

func noArgsWhenHashOrPipe(cmd *cobra.Command, args []string) error {
	if hash, _ := cmd.Flags().GetString("hash"); hash != "" {
		if len(args) > 0 {
			return fmt.Errorf("cannot use ARG(s) with --hash")
		}
		return nil
	}
	if pipeMode() {
		return nil
	}
	return cobra.ExactArgs(1)(cmd, args)
}
