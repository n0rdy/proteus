package conf

import (
	"encoding/base64"
	"github.com/n0rdy/proteus/cmd/utils"
	"github.com/n0rdy/proteus/common"
	"github.com/n0rdy/proteus/logger"
	commonUtils "github.com/n0rdy/proteus/utils"
	"gopkg.in/yaml.v3"
	"os"
	"regexp"
	"strconv"
)

const (
	defaultContentType       = "application/json"
	defaultApiKeyLocation    = "header"
	defaultApiKeyValueFormat = "plain"
)

var (
	supportedContentTypes = map[string]bool{
		"application/json": true,
		"application/xml":  true,
	}
	supportedApiKeyLocations = map[string]bool{
		"header": true,
		"query":  true,
	}
	supportedApiKeyValueFormats = map[string]bool{
		"plain":  true,
		"base64": true,
	}
)

type Parser struct {
}

func (p Parser) Parse(confPath string) (*common.Conf, error) {
	if confPath == "" {
		return nil, nil
	}

	confAsBytes, err := os.ReadFile(confPath)
	if err != nil {
		logger.Error("failed to open configuration file ["+confPath+"]", err)
		return nil, err
	}

	conf := &common.Conf{}
	err = yaml.Unmarshal(confAsBytes, conf)
	if err != nil {
		logger.Error("failed to parse configuration file ["+confPath+"]", err)
		return nil, err
	}

	err = p.validate(conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func (p Parser) validate(conf *common.Conf) error {
	if conf.Rest != nil {
		restHints := conf.Rest.Hints
		if restHints != nil {
			statusCode := restHints.StatusCode
			if statusCode != 0 && (statusCode < 100 || statusCode > 599) {
				logger.Error("Invalid HTTP status code: should be in range [100, 599], got: [" + strconv.Itoa(statusCode) + "]")
				return utils.ErrInvalidConfigFile
			}

			responseBody := restHints.ResponseBody
			if responseBody != nil {
				if commonUtils.AllPresent(responseBody.Plain, responseBody.Base64) {
					logger.Error("Either plain or base64-encoded response body should be provided, not both")
					return utils.ErrInvalidConfigFile
				}
				if responseBody.ContentType != "" && !supportedContentTypes[responseBody.ContentType] {
					logger.Error("Unsupported content type [" + responseBody.ContentType + "]")
					return utils.ErrInvalidConfigFile
				}
				if commonUtils.NonePresent(responseBody.Plain, responseBody.Base64) && responseBody.ContentType != "" {
					logger.Error("Response body is not provided, but content type is [" + responseBody.ContentType + "]")
					return utils.ErrInvalidConfigFile
				}
				if commonUtils.AnyPresent(responseBody.Plain, responseBody.Base64) && responseBody.ContentType == "" {
					logger.Debug("Content type is not provided, assuming [application/json] as the default value")
					conf.Rest.Hints.ResponseBody.ContentType = defaultContentType
				}
			}

			if restHints.WaitMs < 0 {
				logger.Error("Invalid wait ms: should be non-negative, got: [" + strconv.FormatInt(restHints.WaitMs, 10) + "]")
				return utils.ErrInvalidConfigFile
			}

			apiKey := restHints.ApiKey
			if apiKey != nil {
				if apiKey.Location != "" && !supportedApiKeyLocations[apiKey.Location] {
					logger.Error("Unsupported API key location [" + apiKey.Location + "]")
					return utils.ErrInvalidConfigFile
				}
				if apiKey.Location == "" {
					logger.Debug("API key location is not provided, assuming [header] as the default value")
					conf.Rest.Hints.ApiKey.Location = defaultApiKeyLocation
				}

				apiKeyValue := apiKey.Value
				if apiKeyValue != nil {
					if apiKeyValue.Format != "" && !supportedApiKeyValueFormats[apiKeyValue.Format] {
						logger.Error("Unsupported API key value format [" + apiKeyValue.Format + "]")
						return utils.ErrInvalidConfigFile
					}
					if apiKeyValue.Format == "" {
						logger.Debug("API key value format is not provided, assuming [plain] as the default value")
						conf.Rest.Hints.ApiKey.Value.Format = defaultApiKeyValueFormat
					}

					apiKeyValueParser := apiKeyValue.Parser
					if apiKeyValueParser != nil {
						// decode from base64
						decoded, err := base64.StdEncoding.DecodeString(apiKeyValueParser.RegexpBase64)
						if err != nil {
							logger.Error("provided api key value parser regexp is not a valid base64 string", err)
							return utils.ErrInvalidConfigFile
						}

						// compile regexp
						_, err = regexp.Compile(string(decoded))
						if err != nil {
							logger.Error("provided api key value parser regexp is not a valid regexp: ["+string(decoded)+"]", err)
							return utils.ErrInvalidConfigFile
						}
					}
				}
			}
		}
	}
	return nil
}
