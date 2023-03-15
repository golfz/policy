package policy

import (
	"github.com/mastertech-hq/authority/resources"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPolicy_IsAccessAllowed(t *testing.T) {

}

func TestPolicy_getStatementsForResource(t *testing.T) {
	strPolicy := `
	{
		"Version": 1,
		"PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		"Statement": [	
			{
				"Effect": "Allow",
				"Resource": "res:::leave",
				"Action": [
					"act:::leave:approve"
				],
				"Condition": {
					"AtLeastOne": {
						"StringIn": {
							"prop:::employee:employee_uuid": [
								"11111111",  
                            	"22222222",  
                            	"33333333",  
                            	"44444444" 
							]	
						}
					},  
					"MustHaveAll": {  
						"DateRange": {  
							"sys:::now:date": {   
								"to": "2023-01-31"  
							}                    
						}                
					}  
				}	
			}
		]
	}`
	p, err := ParseJSON([]byte(strPolicy))
	assert.NoError(t, err)

	res := resources.Resource{
		Resource: "res:::leave",
		Action:   "act:::leave:approve",
		Properties: resources.Property{
			String: map[string]string{
				"prop:::employee:employee_uuid": "11111111",
			},
		},
	}

	statements, err := p.getStatementsForResource(res)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(statements))
}
