package hints

import (
	"encoding/base64"
	"github.com/n0rdy/proteus/common"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/utils"
	"github.com/n0rdy/proteus/logger"
	commonUtils "github.com/n0rdy/proteus/utils"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ProteusHintsParser struct {
	InitConf *models.ProteusHints
}

// Init accepts the configuration and initializes the parser with the hints from the configuration.
// These init configs have the lowest priority since they are global.
// That's why the idea is to provide an easy way to override them via query params, headers, or cookies.
func (php *ProteusHintsParser) Init(conf *common.Conf) {
	if conf == nil || conf.Rest == nil || conf.Rest.Hints == nil {
		return
	}

	initConf := models.ProteusHints{}

	restHints := conf.Rest.Hints
	if restHints.StatusCode != 0 {
		initConf.StatusCode = restHints.StatusCode
	}
	if restHints.ResponseBody != nil {
		if restHints.ResponseBody.Plain != "" {
			initConf.Body = []byte(restHints.ResponseBody.Plain)
		} else if restHints.ResponseBody.Base64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(restHints.ResponseBody.Base64)
			if err != nil {
				logger.Error("response hints: response body: failed to decode base64 string - ignoring response body")
			} else {
				initConf.Body = decoded
			}
		}
		if restHints.ResponseBody.ContentType != "" {
			initConf.ContentType = restHints.ResponseBody.ContentType
		}
	}
	if restHints.RedirectLocation != "" {
		initConf.RedirectLocation = restHints.RedirectLocation
	}
	if restHints.WaitMs != 0 {
		initConf.Wait = time.Duration(restHints.WaitMs) * time.Millisecond
	}
	if restHints.ApiKey != nil {
		apiKey := restHints.ApiKey
		if apiKey.Name != "" {
			initConfApiKey := &models.ProteusHintsApiKeyAuth{}
			initConfApiKey.KeyName = apiKey.Name
			initConfApiKey.Location = apiKey.Location

			if apiKey.Value != nil {
				initConfApiKey.ValueFormat = apiKey.Value.Format
				if apiKey.Value.Parser != nil {
					// ignoring errors here, because we did validation in the config parser
					decoded, _ := base64.StdEncoding.DecodeString(apiKey.Value.Parser.RegexpBase64)
					compiled, _ := regexp.Compile(string(decoded))
					initConfApiKey.ValueParserRegexp = compiled
				}
			}

			initConf.ApiKey = initConfApiKey
		}
	}

	if php.isEmpty(initConf) {
		return
	}
	php.InitConf = &initConf
}

func (php *ProteusHintsParser) ParseHints(req *http.Request) *models.ProteusHints {
	hintsFromQueryParams := php.parseQueryParamsForHints(req.URL.Query())
	hintsFromHeaders := php.parseHeadersForHints(req.Header)
	hintsFromCookies := php.parseCookiesForHints(req.Cookies())
	return php.mergeHints(hintsFromQueryParams, hintsFromHeaders, hintsFromCookies)
}

func (php *ProteusHintsParser) isEmpty(hints models.ProteusHints) bool {
	return hints.StatusCode == 0 && len(hints.Body) == 0 &&
		hints.ContentType == "" && hints.RedirectLocation == "" && hints.Wait == 0 &&
		(hints.ApiKey == nil || (hints.ApiKey.KeyName == "" && hints.ApiKey.Location == "" && hints.ApiKey.ValueFormat == "" && hints.ApiKey.ValueParserRegexp == nil))
}

func (php *ProteusHintsParser) parseQueryParamsForHints(queryParams url.Values) *models.ProteusHints {
	statusCodeQP := queryParams.Get(utils.StatusCodeQueryParam)
	statusCodeAsInt, err := strconv.Atoi(statusCodeQP)
	if err != nil {
		statusCodeAsInt = 0
	}
	if statusCodeAsInt < 100 || statusCodeAsInt > 599 {
		statusCodeAsInt = 0
	}

	var respBodyAsBytes []byte

	respBodyAsString := queryParams.Get(utils.ResponseBodyQueryParam)
	if respBodyAsString != "" {
		respBodyAsBytes = []byte(respBodyAsString)
	} else if respBodyAsBase64 := queryParams.Get(utils.ResponseBodyBase64QueryParam); respBodyAsBase64 != "" {
		respBodyAsBytes, err = base64.StdEncoding.DecodeString(respBodyAsBase64)
		if err != nil {
			respBodyAsBytes = []byte{}
		}
	}

	contentType := queryParams.Get(utils.ResponseBodyContentTypeQueryParam)
	var redirectLocation string
	if utils.RequireRedirect(statusCodeAsInt) {
		redirectLocation = queryParams.Get(utils.RedirectLocationQueryParam)
	}

	waitMs := queryParams.Get(utils.WaitMsQueryParam)
	waitMsAsInt, err := strconv.Atoi(waitMs)
	if err != nil {
		waitMsAsInt = 0
	}

	apiKeyName := queryParams.Get(utils.ApiKeyNameQueryParam)
	apiKeyLocation := strings.ToLower(queryParams.Get(utils.ApiKeyLocationQueryParam))
	if apiKeyLocation != "header" && apiKeyLocation != "query" {
		apiKeyLocation = ""
	}

	apiKeyValueFormat := strings.ToLower(queryParams.Get(utils.ApiKeyValueFormatQueryParam))
	if apiKeyValueFormat != "plain" && apiKeyValueFormat != "base64" {
		apiKeyValueFormat = ""
	}

	apiKeyValueParserRegexpBase64 := queryParams.Get(utils.ApiKeyValueParserRegexpBase64QueryParam)

	if php.nothingProvided(statusCodeAsInt, respBodyAsBytes, contentType, waitMsAsInt, apiKeyName, apiKeyLocation, apiKeyValueFormat, apiKeyValueParserRegexpBase64) {
		return nil
	}

	return &models.ProteusHints{
		StatusCode:       statusCodeAsInt,
		Body:             respBodyAsBytes,
		ContentType:      contentType,
		RedirectLocation: redirectLocation,
		Wait:             time.Duration(waitMsAsInt) * time.Millisecond,
		ApiKey:           php.apiKey(apiKeyName, apiKeyLocation, apiKeyValueFormat, apiKeyValueParserRegexpBase64),
	}
}

func (php *ProteusHintsParser) parseHeadersForHints(headers http.Header) *models.ProteusHints {
	statusCode := headers.Get(utils.StatusCodeHeader)
	statusCodeAsInt, err := strconv.Atoi(statusCode)
	if err != nil {
		statusCodeAsInt = 0
	}

	var respBodyAsBytes []byte
	respBodyAsString := headers.Get(utils.ResponseBodyHeader)
	if respBodyAsString != "" {
		respBodyAsBytes = []byte(respBodyAsString)
	} else if respBodyAsBase64 := headers.Get(utils.ResponseBodyBase64Header); respBodyAsBase64 != "" {
		respBodyAsBytes, err = base64.StdEncoding.DecodeString(respBodyAsBase64)
		if err != nil {
			respBodyAsBytes = []byte{}
		}
	}

	contentType := headers.Get(utils.ResponseBodyContentTypeHeader)
	var redirectLocation string
	if utils.RequireRedirect(statusCodeAsInt) {
		redirectLocation = headers.Get(utils.RedirectLocationHeader)
	}

	waitMs := headers.Get(utils.WaitMsHeader)
	waitMsAsInt, err := strconv.Atoi(waitMs)
	if err != nil {
		waitMsAsInt = 0
	}

	apiKeyName := headers.Get(utils.ApiKeyNameHeader)
	apiKeyLocation := strings.ToLower(headers.Get(utils.ApiKeyLocationHeader))
	if apiKeyLocation != "header" && apiKeyLocation != "query" {
		apiKeyLocation = ""
	}

	apiKeyValueFormat := strings.ToLower(headers.Get(utils.ApiKeyValueFormatHeader))
	if apiKeyValueFormat != "plain" && apiKeyValueFormat != "base64" {
		apiKeyValueFormat = ""
	}

	apiKeyValueParserRegexpBase64 := headers.Get(utils.ApiKeyValueParserRegexpBase64Header)

	if php.nothingProvided(statusCodeAsInt, respBodyAsBytes, contentType, waitMsAsInt, apiKeyName, apiKeyLocation, apiKeyValueFormat, apiKeyValueParserRegexpBase64) {
		return nil
	}

	return &models.ProteusHints{
		StatusCode:       statusCodeAsInt,
		Body:             respBodyAsBytes,
		ContentType:      contentType,
		RedirectLocation: redirectLocation,
		Wait:             time.Duration(waitMsAsInt) * time.Millisecond,
		ApiKey:           php.apiKey(apiKeyName, apiKeyLocation, apiKeyValueFormat, apiKeyValueParserRegexpBase64),
	}
}

func (php *ProteusHintsParser) parseCookiesForHints(cookies []*http.Cookie) *models.ProteusHints {
	statusCode := php.getCookieValue(cookies, utils.StatusCodeCookie)
	statusCodeAsInt, err := strconv.Atoi(statusCode)
	if err != nil {
		statusCodeAsInt = 0
	}

	var respBodyAsBytes []byte
	respBodyAsString := php.getCookieValue(cookies, utils.ResponseBodyCookie)
	if respBodyAsString != "" {
		respBodyAsBytes = []byte(respBodyAsString)
	} else if respBodyAsBase64 := php.getCookieValue(cookies, utils.ResponseBodyBase64Cookie); respBodyAsBase64 != "" {
		respBodyAsBytes, err = base64.StdEncoding.DecodeString(respBodyAsBase64)
		if err != nil {
			respBodyAsBytes = []byte{}
		}
	}

	contentType := php.getCookieValue(cookies, utils.ResponseBodyContentTypeCookie)
	var redirectLocation string
	if utils.RequireRedirect(statusCodeAsInt) {
		redirectLocation = php.getCookieValue(cookies, utils.RedirectLocationCookie)
	}

	waitMs := php.getCookieValue(cookies, utils.WaitMsCookie)
	waitMsAsInt, err := strconv.Atoi(waitMs)
	if err != nil {
		waitMsAsInt = 0
	}

	apiKeyName := php.getCookieValue(cookies, utils.ApiKeyNameCookie)
	apiKeyLocation := php.getCookieValue(cookies, utils.ApiKeyLocationCookie)
	if apiKeyLocation != "header" && apiKeyLocation != "query" {
		apiKeyLocation = ""
	}

	apiKeyValueFormat := php.getCookieValue(cookies, utils.ApiKeyValueFormatCookie)
	if apiKeyValueFormat != "plain" && apiKeyValueFormat != "base64" {
		apiKeyValueFormat = ""
	}

	apiKeyValueParserRegexpBase64 := php.getCookieValue(cookies, utils.ApiKeyValueParserRegexpBase64Cookie)

	if php.nothingProvided(statusCodeAsInt, respBodyAsBytes, contentType, waitMsAsInt, apiKeyName, apiKeyLocation, apiKeyValueFormat, apiKeyValueParserRegexpBase64) {
		return nil
	}

	return &models.ProteusHints{
		StatusCode:       statusCodeAsInt,
		Body:             respBodyAsBytes,
		ContentType:      contentType,
		RedirectLocation: redirectLocation,
		Wait:             time.Duration(waitMsAsInt) * time.Millisecond,
		ApiKey:           php.apiKey(apiKeyName, apiKeyLocation, apiKeyValueFormat, apiKeyValueParserRegexpBase64),
	}
}

func (php *ProteusHintsParser) apiKey(keyName string, location string, valueFormat string, valueParserRegexpBase64 string) *models.ProteusHintsApiKeyAuth {
	var valueParserRegexp *regexp.Regexp
	if valueParserRegexpBase64 != "" {
		// decode from base64
		decoded, err := base64.StdEncoding.DecodeString(valueParserRegexpBase64)
		if err != nil {
			logger.Error("response hints: apiKey: valueParserRegexpBase64 is not a valid base64 string - ignoring all the apiKey hints")
			return nil
		}

		// compile regexp
		valueParserRegexp, err = regexp.Compile(string(decoded))
		if err != nil {
			logger.Error("response hints: apiKey: valueParserRegexpBase64 is not a valid regexp - ignoring all the apiKey hints")
			return nil
		}
	}

	var apiKey *models.ProteusHintsApiKeyAuth
	if commonUtils.AnyPresent(keyName, location, valueFormat, valueParserRegexpBase64) {
		apiKey = &models.ProteusHintsApiKeyAuth{
			KeyName:           keyName,
			Location:          location,
			ValueFormat:       valueFormat,
			ValueParserRegexp: valueParserRegexp,
		}
	}
	return apiKey
}

func (php *ProteusHintsParser) getCookieValue(cookies []*http.Cookie, cookieName string) string {
	for _, cookie := range cookies {
		if cookie.Name == cookieName {
			return cookie.Value
		}
	}
	return ""
}

func (php *ProteusHintsParser) nothingProvided(
	statusCode int,
	respBody []byte,
	contentType string,
	waitMs int,
	apiKeyName string,
	apiKeyLocation string,
	apiKeyValueFormat string,
	apiKeyValueParserRegexpBase64 string,
) bool {
	return statusCode == 0 && len(respBody) == 0 && contentType == "" && waitMs == 0 &&
		apiKeyName == "" && apiKeyLocation == "" && apiKeyValueFormat == "" && apiKeyValueParserRegexpBase64 == ""
}

func (php *ProteusHintsParser) mergeHints(
	hintsFromQueryParams, hintsFromHeaders, hintsFromCookies *models.ProteusHints,
) *models.ProteusHints {
	if hintsFromQueryParams == nil && hintsFromHeaders == nil && hintsFromCookies == nil {
		return nil
	}

	result := &models.ProteusHints{}

	// the priority is: query params > headers > cookies > init conf
	if php.InitConf != nil {
		php.fillHints(result, php.InitConf)
	}
	if hintsFromCookies != nil {
		php.fillHints(result, hintsFromCookies)
	}
	if hintsFromHeaders != nil {
		php.fillHints(result, hintsFromHeaders)
	}
	if hintsFromQueryParams != nil {
		php.fillHints(result, hintsFromQueryParams)
	}

	// if body is empty but content type is not, then we should reset the content type
	if len(result.Body) == 0 && result.ContentType != "" {
		logger.Warn("response hints: body is empty but content type is not - ignoring content type")
		result.ContentType = ""
	}

	// if apiKey is provided but keyName is empty, then we should reset the apiKey
	if result.ApiKey != nil && result.ApiKey.KeyName == "" {
		logger.Warn("response hints: apiKey is provided but keyName is empty - ignoring apiKey")
		result.ApiKey = nil
	}

	return result
}

func (php *ProteusHintsParser) fillHints(result *models.ProteusHints,
	source *models.ProteusHints) {
	if source.StatusCode != 0 {
		result.StatusCode = source.StatusCode
	}
	if len(source.Body) != 0 {
		result.Body = source.Body
	}
	if source.ContentType != "" {
		result.ContentType = source.ContentType
	}
	if source.RedirectLocation != "" {
		result.RedirectLocation = source.RedirectLocation
	}
	if source.Wait != 0 {
		result.Wait = source.Wait
	}

	if source.ApiKey != nil {
		if source.ApiKey.KeyName != "" {
			if result.ApiKey == nil {
				result.ApiKey = &models.ProteusHintsApiKeyAuth{}
			}
			result.ApiKey.KeyName = source.ApiKey.KeyName
		}
		if source.ApiKey.Location != "" {
			if result.ApiKey == nil {
				result.ApiKey = &models.ProteusHintsApiKeyAuth{}
			}
			result.ApiKey.Location = source.ApiKey.Location
		}
		if source.ApiKey.ValueFormat != "" {
			if result.ApiKey == nil {
				result.ApiKey = &models.ProteusHintsApiKeyAuth{}
			}
			result.ApiKey.ValueFormat = source.ApiKey.ValueFormat
		}
		if source.ApiKey.ValueParserRegexp != nil {
			if result.ApiKey == nil {
				result.ApiKey = &models.ProteusHintsApiKeyAuth{}
			}
			result.ApiKey.ValueParserRegexp = source.ApiKey.ValueParserRegexp
		}
	}
}
