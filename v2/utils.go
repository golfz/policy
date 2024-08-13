package policy

func isContainsInList[T comparable](list []T, s T) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func isEquals[T comparable](a, b T) bool {
	return a == b
}
