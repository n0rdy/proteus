package utils

import (
	"errors"
	"fmt"
)

const (
	errWrongFormattedIntFlagTemplate    = "wrong formatted flag [%s] - expected to be of type int32"
	errWrongFormattedStringFlagTemplate = "wrong formatted flag [%s] - expected to be of type string"
)

var (
	ErrCmdInvalidPort    = errors.New("port should be provided as an integer value in range [0, 65535]")
	ErrInvalidConfigFile = errors.New("invalid config file")
)

func ErrWrongFormattedIntFlag(flagName string) error {
	return errors.New(fmt.Sprintf(errWrongFormattedIntFlagTemplate, flagName))
}

func ErrWrongFormattedStringFlag(flagName string) error {
	return errors.New(fmt.Sprintf(errWrongFormattedStringFlagTemplate, flagName))
}
