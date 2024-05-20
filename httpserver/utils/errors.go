package utils

import "errors"

var (
	ErrReservedPath                 = errors.New("proteus: path is reserved")
	ErrDuplicatedContentType        = errors.New("proteus: content type is duplicated for one of HTTP codes - check logs for more details")
	ErrNoTypeSpecifiedOpenApi       = errors.New("proteus: no type specified for OpenAPI schema property")
	ErrUnsupportedSchemaTypeOpenApi = errors.New("proteus: unsupported schema type for OpenAPI")
	ErrNoItemsSpecifiedOpenApi      = errors.New("proteus: no items specified for OpenAPI schema property")
	ErrMediaTypeNotFound            = errors.New("proteus: media type not found")
)
