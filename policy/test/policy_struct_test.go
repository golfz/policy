package test

import (
	"github.com/mastertech-hq/authority/policy"
	"github.com/mastertech-hq/authority/resources"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsAccessAllowed_AAA(t *testing.T) {
	strPolicy := `{
		"Version": 1,
		"User": {
			"UserID": "Bob",
			"UserType": "employee"
		},
		"Statement": [	
			{
				"Effect": "Allow",
				"Resource": "res:::leave",
				"Action": ["act:::leave:approve"],
				"Condition": {
					"AtLeastOne": {
						"StringIn": {
							"prop:::employee:employee_uuid": [
								"Bob",
								"Adams"
							]	
						}
					}
				}	
			}
		]
	}`
	p, err := policy.ParseJSON([]byte(strPolicy))
	assert.NoError(t, err)

	res := resources.Resource{
		Resource: "res:::leave",
		Action:   "act:::leave:approve",
		Properties: resources.Property{
			String: map[string]string{
				"prop:::employee:employee_uuid":     "Bob",
				"prop:::employee:organization_uuid": "Bob",
				"prop:::employee:company_uuid":      "Bob",
			},
		},
	}

	valid, err := p.IsAccessAllowed(res)
	assert.NoError(t, err)
	assert.True(t, valid)
}
