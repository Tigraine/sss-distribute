package main

import (
	"bytes"
	"crypto/rand"
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
		file, err := cmd.Flags().GetBool("file")
		if err != nil {
			return err
		}

		parts := make([][]byte, len(args))
		for i, fName := range args {
			if file {
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
			parts[i], err = hex.DecodeString(args[i])
			if err != nil {
				return err
			}
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
	Short: "Split a secret using Shamir's Secret Sharing",
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

		encryptInput, err := cmd.Flags().GetBool("encrypt")
		if err != nil {
			return err
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

		if encryptInput {
			f, err := encryptInputUsingGPG(file)
			file = []byte(f)
			if err != nil {
				return err
			}
		}

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

func generateKey(i int) ([]byte, error) {
	out := make([]byte, i)
	_, err := rand.Read(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func encryptInputUsingGPG(input []byte) (string, error) {
	bKey, err := generateKey(8)
	if err != nil {
		return "", err
	}
	key := hex.EncodeToString(bKey)
	command := exec.Command("gpg", "--symmetric", "--batch", "--yes", "--passphrase", key, "-o secret.asc")
	command.Stdin = bytes.NewReader(input)
	err = command.Run()
	fmt.Println("Encrypted input using GPG to secret.asc")
	return key, err
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
	Long: "sss-distribute allows you to encrypt and decrypt secrets that are split into multiple parts\n" +
		"Shamir Secret Sharing allows the secure distribution of secrets among of group of people\n" +
		"while requiring multiple people to come together to reconstruct the secret together\n" +
		"An example for this would be for example a infrequently used Super-Admin password that's only used during desaster recovery\n",
	Example: "Distribute contents of secret.txt among 5 people while requiring at least 3 parts to reconstruct secret.txt:\n" +
		"$ sss-distribute encrypt --parts 5 --threshold 3 --input secret.txt\n" +
		"Distribute contents of secret.txt and encrypt the parts using gpg public keys (most secure)\n" +
		"$ sss-distribute encrypt -p 3 -t 2 --input secret.txt --gpg alice@test.com bob@test.com charly@test.com\n" +
		"Decrypt a previously given secret using 2 parts:\n" +
		"$ sss-distribute decrypt <secret1> <secret2>\n" +
		"Decrypt a previously given secret reading the parts from files on disk:\n" +
		"$ sss-distribute decrypt --file part1.txt part2.txt",
	DisableFlagsInUseLine: true,
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
	encryptCmd.Flags().Bool("encrypt", false, "Encrypt the input using GPG and distribute the encrypted secret using Shamir")

	decryptCmd.Flags().BoolP("file", "f", false, "Read the secret parts from files")

	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(encryptCmd)
	err := rootCmd.Execute()
	if err != nil {
		fmt.Printf("Error executing command: %s", err)
	}

}
