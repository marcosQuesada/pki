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

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate Public/Private keys",
	Long: `Generate Public/Private keys, both are dumped to StdOut`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("generate called")
		key, err := pki.New()
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(key.PublicKeyToPemString())
		fmt.Println(key.PrivateKeyToPemString())
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
}
