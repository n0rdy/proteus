package common

const (
	// Proteus API error messages
	ErrorInvalidStatusCode         = "proteus: invalid status code: [%s]"
	ErrorInvalidRequestBody        = "proteus: invalid request body"
	ErrorInvalidSmartRequestPath   = "proteus: invalid smart request path: [%s] - it must contain at least one path parameter after the [/smart] path segment"
	ErrorNotFoundSmartPath         = "proteus: smart domain path not found: [%s]"
	ErrorInvalidSmartRequestMethod = "proteus: invalid smart request method: [%s] - only GET, POST, PUT and DELETE are supported"
	ErrorResponseMarshalling       = "proteus: marshalling response"
	ErrorInternalServerError       = "proteus: internal server error"

	// Proteus API error codes
	ErrorCodeInvalidStatusCode          = "proteus.bad_request.status_code"
	ErrorCodeInvalidRequestBody         = "proteus.bad_request.request_body"
	ErrorCodeInvalidSmartRequestPath    = "proteus.not_found.invalid_smart_request_path"
	ErrorCodeNotFoundSmartPath          = "proteus.not_found.smart_path"
	ErrorCodeInvalidSmartRequestMethod  = "proteus.method_not_allowed.smart_request_method"
	ErrorCodeResponseMarshalling        = "proteus.internal.response_body_marshaling"
	ErrorCodeInternalInvalidRequestPath = "proteus.internal.request_path"

	// query params to manage desired response
	StatusCodeQueryParam              = "proteus_status_code"
	ResponseBodyQueryParam            = "proteus_response_body"
	ResponseBodyBase64QueryParam      = "proteus_response_body_base64"
	ResponseBodyContentTypeQueryParam = "proteus_response_content_type"
	RedirectLocationQueryParam        = "proteus_redirect_location"
	WaitMsQueryParam                  = "proteus_wait_ms"

	// headers to manage desired response
	StatusCodeHeader              = "X-Proteus-Status-Code"
	ResponseBodyHeader            = "X-Proteus-Response-Body"
	ResponseBodyBase64Header      = "X-Proteus-Response-Body-Base64"
	ResponseBodyContentTypeHeader = "X-Proteus-Response-Content-Type"
	RedirectLocationHeader        = "X-Proteus-Redirect-Location"
	WaitMsHeader                  = "X-Proteus-Wait-Ms"

	// cookies to manage desired response
	StatusCodeCookie              = "proteus_status_code"
	ResponseBodyCookie            = "proteus_response_body"
	ResponseBodyBase64Cookie      = "proteus_response_body_base64"
	ResponseBodyContentTypeCookie = "proteus_response_content_type"
	RedirectLocationCookie        = "proteus_redirect_location"
	WaitMsCookie                  = "proteus_wait_ms"

	// other:
	DefaultErrorCodeTpl = "%d.default"

	SmartEndpointPath                    = "/api/v1/proteus/smart"
	SmartEndpointPathWithoutLeadingSlash = "api/v1/proteus/smart"
)
