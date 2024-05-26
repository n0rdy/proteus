package main

import (
	_ "embed"
	"github.com/n0rdy/proteus/cmd"
	"github.com/n0rdy/proteus/cmd/utils"
)

//go:embed docs/examples/config-valid.yaml
var configFileExampleContent []byte

func main() {
	utils.InitExamples(configFileExampleContent)
	cmd.Execute()
}
