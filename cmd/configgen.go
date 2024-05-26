package cmd

import (
	_ "embed"
	"github.com/n0rdy/proteus/cmd/utils"
	"github.com/n0rdy/proteus/logger"
	"os"

	"github.com/spf13/cobra"
)

const (
	configFileName = "proteus-config.yaml"
)

// configgenCmd represents the configgen command
var configgenCmd = &cobra.Command{
	Use:   "configgen",
	Short: "A command to generate the example configuration file for proteus",
	Long: `A command to generate the example configuration file for proteus.

The command creates a new file with the name "proteus-config.yaml" in the directory specified by the "--path" flag.
If the flag is not provided, the file is created in the current working directory.

Please, make sure to check the content of the generated file and adjust it according to your needs.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pathToDir, err := cmd.Flags().GetString(utils.PathFlag)
		if err != nil {
			logger.Error("configgen command: error while parsing flag: "+utils.PathFlag, err)
			return err
		}

		configgenFile := configgenFilePath(pathToDir)
		err = os.WriteFile(configgenFile, utils.ConfigFileExampleContent, 0644)
		if err != nil {
			logger.Error("configgen command: error while writing the config file", err)
			return err
		}
		logger.Info("configgen command: config file has been generated successfully at [" + configgenFile + "]  with content:\n" + string(utils.ConfigFileExampleContent))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(configgenCmd)

	configgenCmd.Flags().StringP(utils.PathFlag, "p", "", "Path to the folder where the configuration file will be generated")
}

func configgenFilePath(pathToDir string) string {
	if pathToDir == "" {
		return configFileName
	}
	return pathToDir + string(os.PathSeparator) + configFileName
}
