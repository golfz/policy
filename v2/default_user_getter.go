package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

type defaultUserPropertyGetter struct {
	userData map[string]interface{}
}

func NewDefaultUserPropertyGetter(userData string) UserPropertyGetter {
	data, err := parseJSON(userData)
	if err != nil {
		return &defaultUserPropertyGetter{userData: make(map[string]interface{})}
	}
	return &defaultUserPropertyGetter{userData: data}
}

func (u *defaultUserPropertyGetter) GetUserProperty(key string) string {
	const (
		prefix    = "user:::"
		separator = ":"
	)
	key = strings.TrimSpace(key)
	key = strings.ReplaceAll(key, prefix, "")
	parts := strings.Split(key, separator)

	var current interface{} = u.userData

	// Navigate through the data for each part of the path.
	for _, part := range parts {
		currentMap, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = currentMap[part]
		if !ok {
			return ""
		}
	}

	return fmt.Sprint(current)
}

func parseJSON(jsonData string) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(jsonData), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
