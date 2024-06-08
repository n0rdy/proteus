package utils

import "embed"

var (
	ConfigFileExampleContent []byte
	OpenApiSpecContent       []byte
	SwaggerUiFs              embed.FS
)

func InitExamples(configFileExampleContent []byte, openApiSpecContent []byte, swaggerUiFs embed.FS) {
	ConfigFileExampleContent = configFileExampleContent
	OpenApiSpecContent = openApiSpecContent
	SwaggerUiFs = swaggerUiFs
}
