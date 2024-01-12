package hints

import (
	"encoding/base64"
	"github.com/n0rdy/proteus/httpserver/common"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/service/logger"
	"github.com/n0rdy/proteus/httpserver/utils"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type ResponseHintsParser struct {
}

func (rhp *ResponseHintsParser) ParseResponseHints(req *http.Request) *models.ResponseHints {
	hintsFromQueyParams := rhp.parseQueryParamsForHints(req.URL.Query())
	hintsFromHeaders := rhp.parseHeadersForHints(req.Header)
	hintsFromCookies := rhp.parseCookiesForHints(req.Cookies())
	return rhp.mergeHints(hintsFromQueyParams, hintsFromHeaders, hintsFromCookies)
}

func (rhp *ResponseHintsParser) parseQueryParamsForHints(queryParams url.Values) *models.ResponseHints {
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

	if rhp.nothingProvided(statusCodeAsInt, respBodyAsBytes, contentType, waitMsAsInt) {
		return nil
	}
	return &models.ResponseHints{
		StatusCode:       statusCodeAsInt,
		Body:             respBodyAsBytes,
		ContentType:      contentType,
		RedirectLocation: redirectLocation,
		Wait:             time.Duration(waitMsAsInt) * time.Millisecond,
	}
}

func (rhp *ResponseHintsParser) parseHeadersForHints(headers http.Header) *models.ResponseHints {
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

	if rhp.nothingProvided(statusCodeAsInt, respBodyAsBytes, contentType, waitMsAsInt) {
		return nil
	}
	return &models.ResponseHints{
		StatusCode:       statusCodeAsInt,
		Body:             respBodyAsBytes,
		ContentType:      contentType,
		RedirectLocation: redirectLocation,
		Wait:             time.Duration(waitMsAsInt) * time.Millisecond,
	}
}

func (rhp *ResponseHintsParser) parseCookiesForHints(cookies []*http.Cookie) *models.ResponseHints {
	statusCode := rhp.getCookieValue(cookies, common.StatusCodeCookie)
	statusCodeAsInt, err := strconv.Atoi(statusCode)
	if err != nil {
		statusCodeAsInt = 0
	}

	var respBodyAsBytes []byte
	respBodyAsString := rhp.getCookieValue(cookies, common.ResponseBodyCookie)
	if respBodyAsString != "" {
		respBodyAsBytes = []byte(respBodyAsString)
	} else if respBodyAsBase64 := rhp.getCookieValue(cookies, common.ResponseBodyBase64Cookie); respBodyAsBase64 != "" {
		respBodyAsBytes, err = base64.StdEncoding.DecodeString(respBodyAsBase64)
		if err != nil {
			respBodyAsBytes = []byte{}
		}
	}

	contentType := rhp.getCookieValue(cookies, common.ResponseBodyContentTypeCookie)
	var redirectLocation string
	if utils.RequireRedirect(statusCodeAsInt) {
		redirectLocation = rhp.getCookieValue(cookies, common.RedirectLocationCookie)
	}

	waitMs := rhp.getCookieValue(cookies, common.WaitMsCookie)
	waitMsAsInt, err := strconv.Atoi(waitMs)
	if err != nil {
		waitMsAsInt = 0
	}

	if rhp.nothingProvided(statusCodeAsInt, respBodyAsBytes, contentType, waitMsAsInt) {
		return nil
	}
	return &models.ResponseHints{
		StatusCode:       statusCodeAsInt,
		Body:             respBodyAsBytes,
		ContentType:      contentType,
		RedirectLocation: redirectLocation,
		Wait:             time.Duration(waitMsAsInt) * time.Millisecond,
	}
}

func (rhp *ResponseHintsParser) getCookieValue(cookies []*http.Cookie, cookieName string) string {
	for _, cookie := range cookies {
		if cookie.Name == cookieName {
			return cookie.Value
		}
	}
	return ""
}

func (rhp *ResponseHintsParser) nothingProvided(statusCode int, respBody []byte, contentType string, waitMs int) bool {
	return statusCode == 0 && len(respBody) == 0 && contentType == "" && waitMs == 0
}

func (rhp *ResponseHintsParser) mergeHints(hintsFromQueryParams, hintsFromHeaders, hintsFromCookies *models.ResponseHints) *models.ResponseHints {
	if hintsFromQueryParams == nil && hintsFromHeaders == nil && hintsFromCookies == nil {
		return nil
	}

	result := &models.ResponseHints{}

	// the priority is: query params > headers > cookies
	if hintsFromCookies != nil {
		rhp.fillHints(result, hintsFromCookies)
	}
	if hintsFromHeaders != nil {
		rhp.fillHints(result, hintsFromHeaders)
	}
	if hintsFromQueryParams != nil {
		rhp.fillHints(result, hintsFromQueryParams)
	}

	// if body is empty but content type is not, then we should reset the content type
	if len(result.Body) == 0 && result.ContentType != "" {
		logger.Warn("response hints: body is empty but content type is not - ignoring content type")
		result.ContentType = ""
	}

	return result
}

func (rhp *ResponseHintsParser) fillHints(result *models.ResponseHints, source *models.ResponseHints) {
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
}
