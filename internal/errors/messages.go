/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */
package errors

import "errors"

const AccountNotSynced = `account not yet synced

We are finalizing your account configuration. We will complete the
configuration shortly and we will update you as soon as this is done.
We are sorry for the inconvenience and would like to thank you for
your patience.
It only takes few seconds. Please try again in 1 minute.`

const AuthRequired = `authentication required, please login`

const UnconfirmedEmail = `your email address was not confirmed

Please confirm it by clicking on the link we sent to %s.
If you did not receive the email, please go to %s and click on the link "Resend email"`

const NoRemainingSignOps = `notarization quota exceeded

Unfortunately, you have used all your notarizations for this month.
If you would like to increase the number of monthly notarizations,
please email us at support@codenotary.io with your request.`

const TrialExpired = `your trial period has been expired

To continue notarizing assets, please purchase a subscription.`

// BlockchainPermission refers to https://github.com/vchain-us/vcn/wiki/Errors#blockchain-permission-403
const BlockchainPermission = `could not write to blockchain

You have not permission to write onto the blockchain (yet).
Please try again later. If the problem persists contact our support.`

const BlockchainTimeout = `writing to blockchain timed out

Please try again later. If the problem persists contact our support.`

const BlockchainCannotConnect = `cannot connect to blockchain

Please try again later. If the problem persists contact our support.`

const BlockchainContractErr = `cannot instantiate contract

Please try again later. If the problem persists contact our support.`

const SignFailed = `method <sign> failed`

var ErrNoLcApiKeyEnv = errors.New(`no API key configured. Please set the environment variable VCN_LC_API_KEY=<API-KEY> or use --lc-api-key flag on each request before running any commands`)
