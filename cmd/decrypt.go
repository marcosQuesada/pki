/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"github.com/marcosQuesada/pki/pkg/pki"
	"log"

	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt using private key",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("decrypt called")
		encryptedMessage := `
-----BEGIN MESSAGE-----
RDPFmUMwZj88pWQRvQHJO2/wFj8JllEr2LKI+A+beueNnh9ZYudib0qy0b3rMMCg
vrKSEdqPOEYD3+Uj2clIjhyiVOvktXV00cC1FVGB0percsMkja8015VuD8kBK1H2
RYe9qeQb35cKz+fqcMzMQrS1rqqj8uMQ2IQqRH+XU7Z67dVBNkUIsfojqoZ8aNZV
0r/sDCZL60oRrtVk7QXHMU+rBgrMoH76Bm15CylZ1IV2m7KcXK9TvjysRnDrYADw
GP2WGi4iWs4XlB2DwOAiQuuNnCqfDuHWge2O5PRP18gt+/fJOzPHjWYrTTqEh6Ga
2Zg3/WC2vy++bmEsv1yuBw==
-----END MESSAGE-----`

		privateKey, err := pki.LoadPrivateKey(serverPrivateKeyPath)
		if err != nil {
			log.Fatalln(err)
		}
		decryptedMessage, err := pki.Decrypt(privateKey, []byte(encryptedMessage))
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(decryptedMessage)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
}
