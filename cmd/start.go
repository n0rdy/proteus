package cmd

import (
	"github.com/n0rdy/proteus/cmd/service/conf"
	"github.com/n0rdy/proteus/cmd/utils"
	"github.com/n0rdy/proteus/httpserver"
	"github.com/n0rdy/proteus/logger"
	commonUtils "github.com/n0rdy/proteus/utils"
	"github.com/spf13/cobra"
	"os"
	"strconv"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proteus app",
	Long: `Start the proteus app.

Under the hood, the command starts an HTTP server at the port provided by the "--port" flag 
or at the default port 14242 if nothing is provided.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		port, err := resolveStartPort(cmd)
		if err != nil {
			return err
		}

		err = os.MkdirAll(commonUtils.GetOsSpecificDbDir(), os.ModePerm)
		if err != nil {
			return err
		}

		confPath, err := cmd.Flags().GetString(utils.ConfigsPathFlag)
		if err != nil {
			logger.Error("change command: error while parsing flag: "+utils.ConfigsPathFlag, err)
			return utils.ErrWrongFormattedStringFlag(utils.ConfigsPathFlag)
		}

		confParser := conf.Parser{}
		conf, err := confParser.Parse(confPath)
		if err != nil {
			return err
		}

		httpserver.Start(port, conf)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)

	startCmd.Flags().IntP(utils.PortFlag, "p", utils.DefaultHttpServerPort, "Port to start the HTTP server at")
	startCmd.Flags().StringP(utils.ConfigsPathFlag, "c", "", "Path to the configuration file")
}

// resolveStartPort resolves the port to start the HTTP server at in the following order:
// 1. From the `--port` flag
// 2. The default port is 14242
func resolveStartPort(cmd *cobra.Command) (int, error) {
	resolvedPort := utils.DefaultHttpServerPort

	// If the port flag is set, use it as the highest priority value
	if cmd.Flags().Changed(utils.PortFlag) {
		port, err := cmd.Flags().GetInt(utils.PortFlag)
		if err != nil {
			logger.Error("start command: error while parsing port flag", err)
			return 0, utils.ErrWrongFormattedIntFlag(utils.PortFlag)
		}
		resolvedPort = port
	}

	if !commonUtils.IsPortValid(resolvedPort) {
		logger.Error("start command: invalid port "+strconv.Itoa(resolvedPort), nil)
		return 0, utils.ErrCmdInvalidPort
	}

	return resolvedPort, nil
}
