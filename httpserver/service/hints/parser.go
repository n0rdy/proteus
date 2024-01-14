package hints

import (
	"encoding/base64"
	"github.com/n0rdy/proteus/httpserver/common"
	"github.com/n0rdy/proteus/httpserver/logger"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/utils"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ProteusHintsParser struct {
}

func (php *ProteusHintsParser) ParseHints(req *http.Request) *models.ProteusHints {
	hintsFromQueryParams := php.parseQueryParamsForHints(req.URL.Query())
	hintsFromHeaders := php.parseHeadersForHints(req.Header)
	hintsFromCookies := php.parseCookiesForHints(req.Cookies())
	return php.mergeHints(hintsFromQueryParams, hintsFromHeaders, hintsFromCookies)
}

func (php *ProteusHintsParser) parseQueryParamsForHints(queryParams url.Values) *models.ProteusHints {
	statusCodeQP := queryParams.Get(common.StatusCodeQueryParam)
	statusCodeAsInt, err := strconv.Atoi(statusCodeQP)
	if err != nil {
		statusCodeAsInt = 0
	}
	if statusCodeAsInt < 100 || statusCodeAsInt > 599 {
		statusCodeAsInt = 0
	}

	var respBodyAsBytes []byte

	respBodyAsString := queryParams.Get(common.ResponseBodyQueryParam)
	if respBodyAsString != "" {
		respBodyAsBytes = []byte(respBodyAsString)
	} else if respBodyAsBase64 := queryParams.Get(common.ResponseBodyBase64QueryParam); respBodyAsBase64 != "" {
		respBodyAsBytes, err = base64.StdEncoding.DecodeString(respBodyAsBase64)
		if err != nil {
			respBodyAsBytes = []byte{}
		}
	}

	contentType := queryParams.Get(common.ResponseBodyContentTypeQueryParam)
	var redirectLocation string
	if utils.RequireRedirect(statusCodeAsInt) {
		redirectLocation = queryParams.Get(common.RedirectLocationQueryParam)
	}

	waitMs := queryParams.Get(common.WaitMsQueryParam)
	waitMsAsInt, err := strconv.Atoi(waitMs)
	if err != nil {
		waitMsAsInt = 0
	}

	apiKeyName := queryParams.Get(common.ApiKeyNameQueryParam)
	apiKeyLocation := strings.ToLower(queryParams.Get(common.ApiKeyLocationQueryParam))
	if apiKeyLocation != "header" && apiKeyLocation != "query" {
		apiKeyLocation = ""
	}

	apiKeyValueFormat := strings.ToLower(queryParams.Get(common.ApiKeyValueFormatQueryParam))
	if apiKeyValueFormat != "plain" && apiKeyValueFormat != "base64" {
		apiKeyValueFormat = ""
	}

	apiKeyValueParserRegexpBase64 := queryParams.Get(common.ApiKeyValueParserRegexpBase64QueryParam)

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
	statusCode := headers.Get(common.StatusCodeHeader)
	statusCodeAsInt, err := strconv.Atoi(statusCode)
	if err != nil {
		statusCodeAsInt = 0
	}

	var respBodyAsBytes []byte
	respBodyAsString := headers.Get(common.ResponseBodyHeader)
	if respBodyAsString != "" {
		respBodyAsBytes = []byte(respBodyAsString)
	} else if respBodyAsBase64 := headers.Get(common.ResponseBodyBase64Header); respBodyAsBase64 != "" {
		respBodyAsBytes, err = base64.StdEncoding.DecodeString(respBodyAsBase64)
		if err != nil {
			respBodyAsBytes = []byte{}
		}
	}

	contentType := headers.Get(common.ResponseBodyContentTypeHeader)
	var redirectLocation string
	if utils.RequireRedirect(statusCodeAsInt) {
		redirectLocation = headers.Get(common.RedirectLocationHeader)
	}

	waitMs := headers.Get(common.WaitMsHeader)
	waitMsAsInt, err := strconv.Atoi(waitMs)
	if err != nil {
		waitMsAsInt = 0
	}

	apiKeyName := headers.Get(common.ApiKeyNameHeader)
	apiKeyLocation := strings.ToLower(headers.Get(common.ApiKeyLocationHeader))
	if apiKeyLocation != "header" && apiKeyLocation != "query" {
		apiKeyLocation = ""
	}

	apiKeyValueFormat := strings.ToLower(headers.Get(common.ApiKeyValueFormatHeader))
	if apiKeyValueFormat != "plain" && apiKeyValueFormat != "base64" {
		apiKeyValueFormat = ""
	}

	apiKeyValueParserRegexpBase64 := headers.Get(common.ApiKeyValueParserRegexpBase64Header)

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
	statusCode := php.getCookieValue(cookies, common.StatusCodeCookie)
	statusCodeAsInt, err := strconv.Atoi(statusCode)
	if err != nil {
		statusCodeAsInt = 0
	}

	var respBodyAsBytes []byte
	respBodyAsString := php.getCookieValue(cookies, common.ResponseBodyCookie)
	if respBodyAsString != "" {
		respBodyAsBytes = []byte(respBodyAsString)
	} else if respBodyAsBase64 := php.getCookieValue(cookies, common.ResponseBodyBase64Cookie); respBodyAsBase64 != "" {
		respBodyAsBytes, err = base64.StdEncoding.DecodeString(respBodyAsBase64)
		if err != nil {
			respBodyAsBytes = []byte{}
		}
	}

	contentType := php.getCookieValue(cookies, common.ResponseBodyContentTypeCookie)
	var redirectLocation string
	if utils.RequireRedirect(statusCodeAsInt) {
		redirectLocation = php.getCookieValue(cookies, common.RedirectLocationCookie)
	}

	waitMs := php.getCookieValue(cookies, common.WaitMsCookie)
	waitMsAsInt, err := strconv.Atoi(waitMs)
	if err != nil {
		waitMsAsInt = 0
	}

	apiKeyName := php.getCookieValue(cookies, common.ApiKeyNameCookie)
	apiKeyLocation := php.getCookieValue(cookies, common.ApiKeyLocationCookie)
	if apiKeyLocation != "header" && apiKeyLocation != "query" {
		apiKeyLocation = ""
	}

	apiKeyValueFormat := php.getCookieValue(cookies, common.ApiKeyValueFormatCookie)
	if apiKeyValueFormat != "plain" && apiKeyValueFormat != "base64" {
		apiKeyValueFormat = ""
	}

	apiKeyValueParserRegexpBase64 := php.getCookieValue(cookies, common.ApiKeyValueParserRegexpBase64Cookie)

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
			logger.Warn("response hints: apiKey: valueParserRegexpBase64 is not a valid regexp - ignoring all the apiKey hints")
			return nil
		}
	}

	var apiKey *models.ProteusHintsApiKeyAuth
	if utils.AnyPresent(keyName, location, valueFormat, valueParserRegexpBase64) {
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
	return statusCode == 0 && len(respBody) == 0 && contentType == "" && waitMs == 0 && apiKeyName == "" && apiKeyLocation == "" && apiKeyValueFormat == "" && apiKeyValueParserRegexpBase64 == ""
}

func (php *ProteusHintsParser) mergeHints(hintsFromQueryParams, hintsFromHeaders, hintsFromCookies *models.ProteusHints) *models.ProteusHints {
	if hintsFromQueryParams == nil && hintsFromHeaders == nil && hintsFromCookies == nil {
		return nil
	}

	result := &models.ProteusHints{}

	// the priority is: query params > headers > cookies
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

func (php *ProteusHintsParser) fillHints(result *models.ProteusHints, source *models.ProteusHints) {
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
