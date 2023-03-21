package policy

import "encoding/json"

func ParseJSON(data []byte) (Policy, error) {
	var p Policy
	err := json.Unmarshal(data, &p)
	return p, err
}
