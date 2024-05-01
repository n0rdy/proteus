package common

import (
	"errors"
	"fmt"
)

const (
	errWrongFormattedIntFlagTemplate = "wrong formatted flag [%s] - expected to be of type int32"
)

var (
	ErrCmdInvalidPort = errors.New("port should be provided as an integer value in range [0, 65535]")
)

func ErrWrongFormattedIntFlag(flagName string) error {
	return errors.New(fmt.Sprintf(errWrongFormattedIntFlagTemplate, flagName))
}
