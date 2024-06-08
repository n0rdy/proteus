package main

import (
	"embed"
	_ "embed"
	"github.com/n0rdy/proteus/cmd"
	"github.com/n0rdy/proteus/utils"
)

//go:embed docs/examples/config-valid.yaml
var configFileExampleContent []byte

//go:embed docs/openapi.yaml
var openApiSpecContent []byte

//go:embed swagger-ui/*
var swaggerUiFs embed.FS

func main() {
	utils.InitEmbeds(configFileExampleContent, openApiSpecContent, swaggerUiFs)
	cmd.Execute()
}
