package main

import (
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"os"
	"os/exec"
	"strings"
)
import "github.com/hashicorp/vault/shamir"

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "decrypt a previously split Shamir secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		parts := make([][]byte, len(args))
		for i, fName := range args {
			contents, err := os.ReadFile(fName)
			if err != nil {
				return err
			}
			b, err := hex.DecodeString(string(contents))
			if err != nil {
				return err
			}
			parts[i] = b
		}
		result, err := shamir.Combine(parts)
		if err != nil {
			return err
		}
		fmt.Println(string(result))
		return nil
	},
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Distribute a secret using Shamir's Secret Sharing",
	RunE: func(cmd *cobra.Command, args []string) error {
		parts, err := cmd.Flags().GetInt("parts")
		if err != nil {
			return err
		}
		threshold, err := cmd.Flags().GetInt("threshold")
		if err != nil {
			return err
		}
		inputFile, err := cmd.Flags().GetString("input")
		if err != nil {
			return err
		}
		yes, err := cmd.Flags().GetBool("yes")
		if err != nil {
			return err
		}

		gpg, err := cmd.Flags().GetBool("gpg")
		if err != nil {
			return err
		}

		if gpg && len(args) != parts {
			return fmt.Errorf("number of recipients must match number of parts")
		}

		var stdinInput []byte
		stat, err := os.Stdin.Stat()
		if err != nil {
			return err
		}
		if stat.Mode()&os.ModeCharDevice == 0 {
			stdinInput, err = io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
		}

		if inputFile == "" && len(stdinInput) == 0 {
			fmt.Printf("No input file provided\n")
			os.Exit(1)
		}
		file := getInputFromStdInOrFile(stdinInput, inputFile)
		partitions, err := shamir.Split(file, parts, threshold)
		if err != nil {
			fmt.Printf("Failed to split secret: %s\n", err)
			os.Exit(1)
		}
		for i, part := range partitions {
			if gpg {
				args := []string{"--encrypt", "--recipient", args[i], "-a", "--output", fmt.Sprintf("part-%d-%s.part", i, args[i])}
				if yes {
					args = append(args, "--yes")
				}
				command := exec.Command("gpg", args...)
				payload := hex.EncodeToString(part)
				command.Stdin = strings.NewReader(payload)
				command.Run()
			} else {
				fmt.Printf("Share %d: %s\n", i+1, hex.EncodeToString(part))
			}
		}
		return nil
	},
}

func getInputFromStdInOrFile(stdIn []byte, inputFile string) []byte {
	if len(stdIn) > 0 {
		return stdIn
	}
	file, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Failed to read input file %s\n", inputFile)
		os.Exit(1)
	}
	return file
}

var rootCmd = &cobra.Command{
	Use: "sss-distribute",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func main() {
	encryptCmd.Flags().IntP("parts", "p", 3, "Number of parts to split the secret into")
	encryptCmd.Flags().IntP("threshold", "t", 2, "Number of parts required to reconstruct the secret")
	encryptCmd.Flags().StringP("input", "i", "", "Input file to encrypt")
	encryptCmd.Flags().BoolP("yes", "y", false, "Don't prompt before overriding output files")
	encryptCmd.Flags().Bool("gpg", false, "Encrypt secret shares with given GPG identities")

	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(encryptCmd)
	err := rootCmd.Execute()
	if err != nil {
		fmt.Printf("Error executing command: %s", err)
	}

}
