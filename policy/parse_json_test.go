package policy

import (
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseJSON(t *testing.T) {
	strPolicy := `{
		"Version": 1,
		"PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		"Statement": [	
			{
				"Effect": "Allow",
				"Resource": "res:::leave",
				"Action": ["act:::leave:approve"],
				"Condition": {
					"AtLeastOne": {
						"StringIn": {
							"prop:::employee:employee_uuid": [
								"501228f3-f7f3-4ef1-8bc9-9fb73347f518",  
                            	"d23b9e25-b0f0-4056-86f0-c104007d1955",  
                            	"e45b9e25-b0f0-4056-86f0-c104007d1904",  
                            	"c78b9e25-b0f0-4056-86f0-c104007d1967" 
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

	assert.Equal(t, 1, p.Version)
	//assert.Equal(t, "Bob", p.Statement[0].Condition.AtLeastOne.StringIn["prop:::employee:employee_uuid"][0])

	spew.Dump(p)

	strJson, err := json.MarshalIndent(p, "", "    ")
	assert.NoError(t, err)
	fmt.Println(string(strJson))
}
