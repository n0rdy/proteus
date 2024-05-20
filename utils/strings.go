package utils

func AnyPresent(values ...string) bool {
	for _, value := range values {
		if value != "" {
			return true
		}
	}
	return false
}

func AllPresent(values ...string) bool {
	for _, value := range values {
		if value == "" {
			return false
		}
	}
	return true
}

func MoreThanOnePresent(values ...string) bool {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
			if count > 1 {
				return true
			}
		}
	}
	return false
}

func NonePresent(values ...string) bool {
	return !AnyPresent(values...)
}
