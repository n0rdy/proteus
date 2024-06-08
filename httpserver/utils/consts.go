package utils

const (
	// Proteus API error messages
	ErrorInvalidStatusCode         = "proteus: invalid status code: [%s]"
	ErrorInvalidRequestBody        = "proteus: invalid request body"
	ErrorInvalidSmartRequestPath   = "proteus: invalid smart request path: [%s] - it must contain at least one path parameter after the [/smart] path segment"
	ErrorInvalidRestEndpointPath   = "proteus: invalid rest endpoint path: [%s] - it must contain be [/api/v1/proteus/admin/rest/endpoints/{method}/{endpointPath}]: either [method] or [endpointPath] is missing"
	ErrorNotFoundSmartPath         = "proteus: smart domain path not found: [%s]"
	ErrorNotFoundRestEndpoint      = "proteus: rest endpoint path not found: [%s]"
	ErrorNotFoundBasicAuthCreds    = "proteus: basic auth credentials not found: [%s]"
	ErrorNotFoundApiKeyAuthCreds   = "proteus: api key auth credentials not found: [%s]"
	ErrorInvalidSmartRequestMethod = "proteus: invalid smart request method: [%s] - only GET, POST, PUT and DELETE are supported"
	ErrorNotAcceptable             = "proteus: media type not found, the predefined ones are [%s]"
	ErrorResponseMarshalling       = "proteus: marshalling response"
	ErrorNotFound                  = "proteus: not found"
	ErrorInternalServerError       = "proteus: internal server error"

	// Proteus API error codes
	ErrorCodeInvalidStatusCode          = "proteus.bad_request.status_code"
	ErrorCodeInvalidRequestBody         = "proteus.bad_request.request_body"
	ErrorCodeInvalidRestEndpointPath    = "proteus.bad_request.invalid_rest_endpoint_request_path"
	ErrorCodeInvalidSmartRequestPath    = "proteus.not_found.invalid_smart_request_path"
	ErrorCodeNotFoundSmartPath          = "proteus.not_found.smart_path"
	ErrorCodeNotFoundRestEndpointPath   = "proteus.not_found.rest_endpoint_path"
	ErrorCodeNotFoundBasicAuthCreds     = "proteus.not_found.basic_auth_creds"
	ErrorCodeNotFoundApiKeyAuthCreds    = "proteus.not_found.api_key_auth_creds"
	ErrorCodeInvalidSmartRequestMethod  = "proteus.method_not_allowed.smart_request_method"
	ErrorCodeNotAcceptable              = "proteus.not_acceptable.media_type"
	ErrorCodeResponseMarshalling        = "proteus.internal.response_body_marshaling"
	ErrorCodeNotFound                   = "proteus.not_found"
	ErrorCodeInternalInvalidRequestPath = "proteus.internal.request_path"

	// query params to manage proteus flow
	StatusCodeQueryParam                    = "proteus_status_code"
	ResponseBodyQueryParam                  = "proteus_response_body"
	ResponseBodyBase64QueryParam            = "proteus_response_body_base64"
	ResponseBodyContentTypeQueryParam       = "proteus_response_content_type"
	RedirectLocationQueryParam              = "proteus_redirect_location"
	WaitMsQueryParam                        = "proteus_wait_ms"
	ApiKeyNameQueryParam                    = "proteus_api_key_name"
	ApiKeyLocationQueryParam                = "proteus_api_key_location"
	ApiKeyValueFormatQueryParam             = "proteus_api_key_value_format"
	ApiKeyValueParserRegexpBase64QueryParam = "proteus_api_key_value_parser_regexp_base64"

	// headers to manage proteus flow
	StatusCodeHeader                    = "X-Proteus-Status-Code"
	ResponseBodyHeader                  = "X-Proteus-Response-Body"
	ResponseBodyBase64Header            = "X-Proteus-Response-Body-Base64"
	ResponseBodyContentTypeHeader       = "X-Proteus-Response-Content-Type"
	RedirectLocationHeader              = "X-Proteus-Redirect-Location"
	WaitMsHeader                        = "X-Proteus-Wait-Ms"
	ApiKeyNameHeader                    = "X-Proteus-Api-Key-Name"
	ApiKeyLocationHeader                = "X-Proteus-Api-Key-Location"
	ApiKeyValueFormatHeader             = "X-Proteus-Api-Key-Value-Format"
	ApiKeyValueParserRegexpBase64Header = "X-Proteus-Api-Key-Value-Parser-Regexp-Base64"

	// cookies to manage proteus flow
	StatusCodeCookie                    = "proteus_status_code"
	ResponseBodyCookie                  = "proteus_response_body"
	ResponseBodyBase64Cookie            = "proteus_response_body_base64"
	ResponseBodyContentTypeCookie       = "proteus_response_content_type"
	RedirectLocationCookie              = "proteus_redirect_location"
	WaitMsCookie                        = "proteus_wait_ms"
	ApiKeyNameCookie                    = "proteus_api_key_name"
	ApiKeyLocationCookie                = "proteus_api_key_location"
	ApiKeyValueFormatCookie             = "proteus_api_key_value_format"
	ApiKeyValueParserRegexpBase64Cookie = "proteus_api_key_value_parser_regexp_base64"

	// other:
	DefaultErrorCodeTpl = "%d.default"

	ProteusReservedApiPath               = "/api/v1/proteus"
	SmartEndpointPath                    = "/api/v1/proteus/smart"
	SmartEndpointPathWithoutLeadingSlash = "api/v1/proteus/smart"
	RestEndpointPath                     = "/api/v1/proteus/admin/rest/endpoints"
)
