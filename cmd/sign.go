package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/marcosQuesada/pki/pkg/pki"
	"log"

	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign message using client private key",
	Long: `Sign message using client private key`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("sign called")
		privateKey, err := pki.LoadPrivateKey(clientPrivateKeyPath)
		if err != nil {
			log.Fatalln(err)
		}
		signature, err := pki.Sign(privateKey, []byte(message))
		if err != nil {
			log.Fatalln(err)
		}

		encodedSignature := base64.StdEncoding.EncodeToString(signature)
		fmt.Println(encodedSignature)
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
}
