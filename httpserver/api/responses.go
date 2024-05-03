package api

import (
	"fmt"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/utils"
	"strconv"
)

var (
	healthOk = models.HealthResponse{Status: "OK"}

	// responses for standard HTTP codes (https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)
	// 1xx:
	_100ContinueResponse   = models.DefaultResponse{Message: "Continue"}
	_101SwitchingProtocols = models.DefaultResponse{Message: "Switching Protocols"}
	_102ProcessingResponse = models.DefaultResponse{Message: "Processing"}
	_103EarlyHintsResponse = models.DefaultResponse{Message: "Early Hints"}

	// 2xx:
	_200OkResponse       = models.DefaultResponse{Message: "OK"}
	_201CreatedResponse  = models.DefaultResponse{Message: "Created"}
	_202AcceptedResponse = models.DefaultResponse{Message: "Accepted"}
	_203NonAuthoritative = models.DefaultResponse{Message: "Non-Authoritative Information"}
	_205ResetContent     = models.DefaultResponse{Message: "Reset Content"}
	_206PartialContent   = models.DefaultResponse{Message: "Partial Content"}
	_207MultiStatus      = models.DefaultResponse{Message: "Multi-Status"}
	_208AlreadyReported  = models.DefaultResponse{Message: "Already Reported"}
	_226IMUsed           = models.DefaultResponse{Message: "IM Used"}

	// 3xx:
	_300MultipleChoicesResponse  = models.DefaultResponse{Message: "Multiple Choices"}
	_301MovedPermanentlyResponse = models.DefaultResponse{Message: "Moved Permanently"}
	_302FoundResponse            = models.DefaultResponse{Message: "Found"}
	_303SeeOtherResponse         = models.DefaultResponse{Message: "See Other"}
	_304NotModifiedResponse      = models.DefaultResponse{Message: "Not Modified"}
	_305UseProxyResponse         = models.DefaultResponse{Message: "Use Proxy"}
	_306SwitchProxyResponse      = models.DefaultResponse{Message: "Switch Proxy"}
	_307TemporaryRedirect        = models.DefaultResponse{Message: "Temporary Redirect"}
	_308PermanentRedirect        = models.DefaultResponse{Message: "Permanent Redirect"}

	// 4xx:
	_400BadRequestResponse           = models.ErrorResponse{Message: "Bad Request", Code: "bad_request.default"}
	_401Unauthorized                 = models.ErrorResponse{Message: "Unauthorized", Code: "unauthorized.default"}
	_402PaymentRequired              = models.ErrorResponse{Message: "Payment Required", Code: "payment_required.default"}
	_403Forbidden                    = models.ErrorResponse{Message: "Forbidden", Code: "forbidden.default"}
	_404NotFound                     = models.ErrorResponse{Message: "Not Found", Code: "not_found.default"}
	_405MethodNotAllowed             = models.ErrorResponse{Message: "Method Not Allowed", Code: "method_not_allowed.default"}
	_406NotAcceptable                = models.ErrorResponse{Message: "Not Acceptable", Code: "not_acceptable.default"}
	_407ProxyAuthRequired            = models.ErrorResponse{Message: "Proxy Authentication Required", Code: "proxy_authentication_required.default"}
	_408RequestTimeout               = models.ErrorResponse{Message: "Request Timeout", Code: "request_timeout.default"}
	_409Conflict                     = models.ErrorResponse{Message: "Conflict", Code: "conflict.default"}
	_410Gone                         = models.ErrorResponse{Message: "Gone", Code: "gone.default"}
	_411LengthRequired               = models.ErrorResponse{Message: "Length Required", Code: "length_required.default"}
	_412PreconditionFailed           = models.ErrorResponse{Message: "Precondition Failed", Code: "precondition_failed.default"}
	_413RequestEntityTooLarge        = models.ErrorResponse{Message: "Request Entity Too Large", Code: "request_entity_too_large.default"}
	_414RequestURITooLong            = models.ErrorResponse{Message: "Request URI Too Long", Code: "request_uri_too_long.default"}
	_415UnsupportedMediaType         = models.ErrorResponse{Message: "Unsupported Media Type", Code: "unsupported_media_type.default"}
	_416RequestedRangeNotSatisfiable = models.ErrorResponse{Message: "Requested Range Not Satisfiable", Code: "requested_range_not_satisfiable.default"}
	_417ExpectationFailed            = models.ErrorResponse{Message: "Expectation Failed", Code: "expectation_failed.default"}
	_418Teapot                       = models.ErrorResponse{Message: "I'm a teapot", Code: "im_a_teapot.default"}
	_421MisdirectedRequest           = models.ErrorResponse{Message: "Misdirected Request", Code: "misdirected_request.default"}
	_422UnprocessableEntity          = models.ErrorResponse{Message: "Unprocessable Entity", Code: "unprocessable_entity.default"}
	_423Locked                       = models.ErrorResponse{Message: "Locked", Code: "locked.default"}
	_424FailedDependency             = models.ErrorResponse{Message: "Failed Dependency", Code: "failed_dependency.default"}
	_425TooEarly                     = models.ErrorResponse{Message: "Too Early", Code: "too_early.default"}
	_426UpgradeRequired              = models.ErrorResponse{Message: "Upgrade Required", Code: "upgrade_required.default"}
	_428PreconditionRequired         = models.ErrorResponse{Message: "Precondition Required", Code: "precondition_required.default"}
	_429TooManyRequests              = models.ErrorResponse{Message: "Too Many Requests", Code: "too_many_requests.default"}
	_431RequestHeaderFieldsTooLarge  = models.ErrorResponse{Message: "Request Header Fields Too Large", Code: "request_header_fields_too_large.default"}
	_451UnavailableForLegalReasons   = models.ErrorResponse{Message: "Unavailable For Legal Reasons", Code: "unavailable_for_legal_reasons.default"}

	// 5xx:
	_500InternalServerError     = models.ErrorResponse{Message: "Internal Server Error", Code: "internal_server_error.default"}
	_501NotImplemented          = models.ErrorResponse{Message: "Not Implemented", Code: "not_implemented.default"}
	_502BadGateway              = models.ErrorResponse{Message: "Bad Gateway", Code: "bad_gateway.default"}
	_503ServiceUnavailable      = models.ErrorResponse{Message: "Service Unavailable", Code: "service_unavailable.default"}
	_504GatewayTimeout          = models.ErrorResponse{Message: "Gateway Timeout", Code: "gateway_timeout.default"}
	_505HTTPVersionNotSupported = models.ErrorResponse{Message: "HTTP Version Not Supported", Code: "http_version_not_supported.default"}
	_506VariantAlsoNegotiates   = models.ErrorResponse{Message: "Variant Also Negotiates", Code: "variant_also_negotiates.default"}
	_507InsufficientStorage     = models.ErrorResponse{Message: "Insufficient Storage", Code: "insufficient_storage.default"}
	_508LoopDetected            = models.ErrorResponse{Message: "Loop Detected", Code: "loop_detected.default"}
	_510NotExtended             = models.ErrorResponse{Message: "Not Extended", Code: "not_extended.default"}
	_511NetworkAuthentication   = models.ErrorResponse{Message: "Network Authentication Required", Code: "network_authentication_required.default"}
)

var statusCodesToResponses = map[int]interface{}{
	100: _100ContinueResponse,
	101: _101SwitchingProtocols,
	102: _102ProcessingResponse,
	103: _103EarlyHintsResponse,
	200: _200OkResponse,
	201: _201CreatedResponse,
	202: _202AcceptedResponse,
	203: _203NonAuthoritative,
	205: _205ResetContent,
	206: _206PartialContent,
	207: _207MultiStatus,
	208: _208AlreadyReported,
	226: _226IMUsed,
	300: _300MultipleChoicesResponse,
	301: _301MovedPermanentlyResponse,
	302: _302FoundResponse,
	303: _303SeeOtherResponse,
	304: _304NotModifiedResponse,
	305: _305UseProxyResponse,
	306: _306SwitchProxyResponse,
	307: _307TemporaryRedirect,
	308: _308PermanentRedirect,
	400: _400BadRequestResponse,
	401: _401Unauthorized,
	402: _402PaymentRequired,
	403: _403Forbidden,
	404: _404NotFound,
	405: _405MethodNotAllowed,
	406: _406NotAcceptable,
	407: _407ProxyAuthRequired,
	408: _408RequestTimeout,
	409: _409Conflict,
	410: _410Gone,
	411: _411LengthRequired,
	412: _412PreconditionFailed,
	413: _413RequestEntityTooLarge,
	414: _414RequestURITooLong,
	415: _415UnsupportedMediaType,
	416: _416RequestedRangeNotSatisfiable,
	417: _417ExpectationFailed,
	418: _418Teapot,
	421: _421MisdirectedRequest,
	422: _422UnprocessableEntity,
	423: _423Locked,
	424: _424FailedDependency,
	425: _425TooEarly,
	426: _426UpgradeRequired,
	428: _428PreconditionRequired,
	429: _429TooManyRequests,
	431: _431RequestHeaderFieldsTooLarge,
	451: _451UnavailableForLegalReasons,
	500: _500InternalServerError,
	501: _501NotImplemented,
	502: _502BadGateway,
	503: _503ServiceUnavailable,
	504: _504GatewayTimeout,
	505: _505HTTPVersionNotSupported,
	506: _506VariantAlsoNegotiates,
	507: _507InsufficientStorage,
	508: _508LoopDetected,
	510: _510NotExtended,
	511: _511NetworkAuthentication,
}

func forStatusCode(statusCode int) interface{} {
	if response, ok := statusCodesToResponses[statusCode]; ok {
		return response
	}
	return createForStatusCode(statusCode)
}

func createForStatusCode(statusCode int) interface{} {
	if statusCode < 400 {
		return models.DefaultResponse{Message: strconv.Itoa(statusCode)}
	} else {
		return models.ErrorResponse{Message: strconv.Itoa(statusCode), Code: fmt.Sprintf(utils.DefaultErrorCodeTpl, statusCode)}
	}
}
