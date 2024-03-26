package policy

import "encoding/json"

func ParsePolicy(b []byte) (Policy, error) {
	var policy Policy
	err := json.Unmarshal(b, &policy)
	return policy, err
}

func ParsePolicyArray(b []byte) ([]Policy, error) {
	var policies []Policy
	if len(b) == 0 {
		return policies, nil
	}
	err := json.Unmarshal(b, &policies)
	return policies, err
}
