package common

type Conf struct {
	Rest *Rest `yaml:"rest,omitempty"`
}

type Rest struct {
	Hints *RestHints `yaml:"hints,omitempty"`
}

type RestHints struct {
	StatusCode       int                    `yaml:"statusCode,omitempty"`
	ResponseBody     *RestHintsResponseBody `yaml:"responseBody,omitempty"`
	RedirectLocation string                 `yaml:"redirectLocation,omitempty"`
	WaitMs           int64                  `yaml:"waitMs,omitempty"`
	ApiKey           *RestHintsApiKey       `yaml:"apiKey,omitempty"`
}

type RestHintsResponseBody struct {
	Plain       string `yaml:"plain,omitempty"`
	Base64      string `yaml:"base64,omitempty"`
	ContentType string `yaml:"contentType,omitempty"`
}

type RestHintsApiKey struct {
	Name     string                `yaml:"name,omitempty"`
	Location string                `yaml:"location,omitempty"`
	Value    *RestHintsApiKeyValue `yaml:"value,omitempty"`
}

type RestHintsApiKeyValue struct {
	Format string                      `yaml:"format,omitempty"`
	Parser *RestHintsApiKeyValueParser `yaml:"parser,omitempty"`
}

type RestHintsApiKeyValueParser struct {
	RegexpBase64 string `yaml:"regexpBase64,omitempty"`
}
