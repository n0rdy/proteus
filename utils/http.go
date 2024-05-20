package utils

import (
	"strconv"
)

var (
	noResponseBodyHttpCodes = map[int]bool{
		204: true,
		205: true,
		304: true,
	}
)

func IsHttpCodeValid(code string) bool {
	codeAsInt, err := strconv.Atoi(code)
	if err != nil {
		return false
	}
	return codeAsInt >= 100 && codeAsInt <= 599
}

func Is2xxHttpCode(code int) bool {
	return code >= 200 && code < 300
}

func IsNoResponseBodyHttpCode(code int) bool {
	return noResponseBodyHttpCodes[code]
}
