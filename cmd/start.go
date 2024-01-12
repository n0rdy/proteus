package cmd

import (
	"github.com/n0rdy/proteus/httpserver"
	"github.com/n0rdy/proteus/httpserver/utils"
	"github.com/spf13/cobra"
	"os"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proteus app",
	Long:  `Start the proteus app.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := os.MkdirAll(utils.GetOsSpecificAppDataDir(), os.ModePerm)
		if err != nil {
			return err
		}

		httpserver.Start(14242)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
