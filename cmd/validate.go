package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/marcosQuesada/pki/pkg/pki"
	"log"

	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate message Signature",
	Long: `Validate message signature using client public key`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("validate called")
		publicKey, err := pki.LoadPublicKey(clientPublicKeyPath)
		if err != nil {
			log.Fatalln(err)
		}

		signature, err := base64.StdEncoding.DecodeString(encodedSignature)
		if err != nil {
			log.Fatalln(err)
		}
		err = pki.VerifySign(publicKey, signature,  []byte(message))
		if err != nil {
			log.Fatalln(err)
		}

		log.Println("Signature validation success")
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
}
