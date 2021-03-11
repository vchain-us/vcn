/*
 * Copyright (c) 2018-2020 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package serve

import (
	"fmt"
	"github.com/spf13/viper"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/vchain-us/vcn/internal/logs"
	"github.com/vchain-us/vcn/pkg/meta"
)

// NewCommand returns the cobra command for `vcn serve`
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a local API server",
		Long: `Start a local API server

In CodeNotary Ledger Compliance mode api key is required. Provide it using x-notarization-lc-api-key header on each request.

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
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return viper.BindPFlags(cmd.Flags())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runServe(cmd)
		},
		Args: cobra.NoArgs,
	}
	cmd.Flags().String("host", "", "host address")
	cmd.Flags().String("port", "8080", "port")
	cmd.Flags().String("tls-cert-file", "", "TLS certificate file")
	cmd.Flags().String("tls-key-file", "", "TLS key file")

	cmd.Flags().String("lc-host", "", meta.VcnLcHostFlagDesc)
	cmd.Flags().String("lc-port", "443", meta.VcnLcPortFlagDesc)
	cmd.Flags().String("lc-cert", "", meta.VcnLcCertPathDesc)
	cmd.Flags().Bool("lc-skip-tls-verify", false, meta.VcnLcSkipTlsVerifyDesc)
	cmd.Flags().Bool("lc-no-tls", false, meta.VcnLcNoTlsDesc)

	return cmd
}

func runServe(cmd *cobra.Command) error {

	host, err := cmd.Flags().GetString("host")
	if err != nil {
		return nil
	}
	port, err := cmd.Flags().GetString("port")
	if err != nil {
		return nil
	}
	addr := host + ":" + port

	certFile, _ := cmd.Flags().GetString("tls-cert-file")
	keyFile, _ := cmd.Flags().GetString("tls-key-file")
	if certFile != "" && keyFile == "" {
		return fmt.Errorf("--tls-key-file is missing")
	}
	if certFile == "" && keyFile != "" {
		return fmt.Errorf("--tls-cert-file is missing")
	}

	lcHost := viper.GetString("lc-host")
	lcPort := viper.GetString("lc-port")
	lcCert := viper.GetString("lc-cert")
	skipTlsVerify := viper.GetBool("lc-skip-tls-verify")
	noTls := viper.GetBool("lc-no-tls")

	sh := handler{
		lcHost:          lcHost,
		lcPort:          lcPort,
		lcCert:          lcCert,
		lcSkipTlsVerify: skipTlsVerify,
		lcNoTls:         noTls,
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", index)
	router.HandleFunc("/notarize", sh.signHandler(meta.StatusTrusted)).Methods("POST")
	router.HandleFunc("/untrust", sh.signHandler(meta.StatusUntrusted)).Methods("POST")
	router.HandleFunc("/unsupport", sh.signHandler(meta.StatusUnsupported)).Methods("POST")
	router.HandleFunc("/authenticate/{hash}", sh.verify).Methods("GET")
	router.HandleFunc("/inspect/{hash}", sh.inspectHandler).Methods("GET")

	logs.LOG.Infof("Log level: %s", logs.LOG.GetLevel().String())
	logs.LOG.Infof("Stage: %s", meta.StageEnvironment().String())

	handler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"POST", "GET", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"content-type", "authorization", "x-notarization-password", "x-notarization-password-empty"}),
	)(router)

	if certFile != "" && keyFile != "" {
		logs.LOG.Infof("Listening on %s (TLS)", addr)
		return http.ListenAndServeTLS(addr, certFile, keyFile, handler)
	}

	logs.LOG.Infof("Listening on %s", addr)
	return http.ListenAndServe(addr, handler)
}

func index(w http.ResponseWriter, r *http.Request) {
	// can be used for healthcheck
	writeResponse(w, http.StatusOK, []byte("OK"))
}
