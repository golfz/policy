package policy

import "encoding/json"

func ParsePolicy(b []byte) (Policy, error) {
	var policy Policy
	err := json.Unmarshal(b, &policy)
	return policy, err
}

func ParsePolicyArray(b []byte) ([]Policy, error) {
	var policies []Policy
	err := json.Unmarshal(b, &policies)
	return policies, err
}
