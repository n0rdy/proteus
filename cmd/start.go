package cmd

import (
	"github.com/n0rdy/proteus/httpserver"
	"github.com/spf13/cobra"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proteus app",
	Long:  `Start the proteus app.`,
	Run: func(cmd *cobra.Command, args []string) {
		httpserver.Start(14242)
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
