package cmd

import (
	"github.com/spf13/cobra"
	"log"
	"os"
)

var (
	clientPublicKeyPath  string
	clientPrivateKeyPath string
	serverPublicKeyPath  string
	serverPrivateKeyPath string
	message              string
	encodedSignature     string
)

var rootCmd = &cobra.Command{
	Use:   "pki service",
	Short: "pki service cli",
	Long:  "pki service cli",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Unexpected execute error, err %v", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&clientPublicKeyPath, "cpub", "b", "./certs/client/public.pem", "Client public key path.")
	rootCmd.PersistentFlags().StringVarP(&clientPrivateKeyPath, "cpriv", "v", "./certs/client/private.pem", "Client private key path.")
	rootCmd.PersistentFlags().StringVarP(&serverPublicKeyPath, "spub", "B", "./certs/server/public.pem", "Server public key path.")
	rootCmd.PersistentFlags().StringVarP(&serverPrivateKeyPath, "spriv", "V", "./certs/server/private.pem", "Server private key path.")
	rootCmd.PersistentFlags().StringVarP(&message, "message", "m", "This is a very secret message :)", "Message to encrypt or sign")
	rootCmd.PersistentFlags().StringVarP(&encodedSignature, "signature", "s", "s+6iHlXK+xoCn0Kr16PhIJcbGyq7s4gu2WBSl7Urgnro4F3AzhmH9QPDKl9r9XKb+/0ARdE633eFANCYEO18CYSM5FhNg1qgSJbojMfsTtUN0AtK9Wf9mExi6Se+PM6QkKnnpgRm+F/PwWpQN9Ke/YHtG4bUVNGHoB2PGPXJVBYk6sCTL1X/Sh2IysAeQ9Jn4Z9xb0lZe9nhCGspLLQwtduR4hDD2rC7DYww6mZrLzOaMHF7KqgD1NDPupAdTMVZyUwVfibOk4TuAtumcc7riXWrxnZccGeEgAV9RViSYe5zHNAcHG606SrBBUOfTlq6Yqf7fdlTBxTnGz5trR2Now==", "base 64 encoded signature")
}
