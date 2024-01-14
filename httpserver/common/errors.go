package common

import "errors"

var (
	ErrReservedPath = errors.New("proteus: path is reserved")
)
