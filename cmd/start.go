package cmd

import (
	"github.com/n0rdy/proteus/cmd/common"
	"github.com/n0rdy/proteus/httpserver"
	"github.com/n0rdy/proteus/logger"
	"github.com/n0rdy/proteus/utils"
	"github.com/spf13/cobra"
	"os"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proteus app",
	Long:  `Start the proteus app.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		port, err := resolveStartPort(cmd)
		if err != nil {
			return err
		}

		err = os.MkdirAll(utils.GetOsSpecificDbDir(), os.ModePerm)
		if err != nil {
			return err
		}

		httpserver.Start(port)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)

	startCmd.Flags().IntP(common.PortFlag, "p", common.DefaultHttpServerPort, "Port to start the HTTP server at")
}

// resolveStartPort resolves the port to start the HTTP server at in the following order:
// 1. From the `--port` flag
// 2. The default port is 14242
func resolveStartPort(cmd *cobra.Command) (int, error) {
	resolvedPort := common.DefaultHttpServerPort

	// If the port flag is set, use it as the highest priority value
	if cmd.Flags().Changed(common.PortFlag) {
		port, err := cmd.Flags().GetInt(common.PortFlag)
		if err != nil {
			logger.Error("start command: error while parsing port flag", err)
			return 0, common.ErrWrongFormattedIntFlag(common.PortFlag)
		}
		resolvedPort = port
	}

	if !utils.IsPortValid(resolvedPort) {
		return 0, common.ErrCmdInvalidPort
	}

	return resolvedPort, nil
}
