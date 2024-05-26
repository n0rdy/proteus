package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "proteus",
	Short: "A tool to mock APIs",
	Long: `A tool to mock APIs.

Run "proteus help" to see the list of available commands.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	versionTemplate := `{{printf "%s version %s\n" .Name .Version}}`
	rootCmd.SetVersionTemplate(versionTemplate)
}
