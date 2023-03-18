package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseJSON(t *testing.T) {
	strPolicy := `
	{
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

	assert.Equal(t, 1, p.Version)
	assert.Equal(t, 1, len(p.Statement))

	assert.NotNil(t, p.Statement[0].Condition.AtLeastOne.StringIn)
	assert.Nil(t, p.Statement[0].Condition.AtLeastOne.StringEqual)
	assert.Contains(t, p.Statement[0].Condition.AtLeastOne.StringIn["prop:::employee:employee_uuid"], "11111111")

	assert.NotNil(t, p.Statement[0].Condition.MustHaveAll.DateRange)
	assert.Empty(t, p.Statement[0].Condition.MustHaveAll.DateRange["sys:::now:date"].From)
}

func TestParseJSON_No_Condition(t *testing.T) {
	strPolicy := `
	{
		"Version": 1,
		"PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		"Statement": [	
			{
				"Effect": "Allow",
				"Resource": "res:::leave",
				"Action": ["act:::leave:approve"]
			}
		]
	}`
	p, err := ParseJSON([]byte(strPolicy))
	assert.NoError(t, err)

	assert.Equal(t, 1, p.Version)
	assert.Equal(t, 1, len(p.Statement))

	assert.Nil(t, p.Statement[0].Condition)
}

func TestParseJSON_No_MustHaveAll(t *testing.T) {
	strPolicy := `
	{
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
								"11111111",  
                            	"22222222",  
                            	"33333333",  
                            	"44444444" 
							]	
						}
					}
				}	
			}
		]
	}`
	p, err := ParseJSON([]byte(strPolicy))
	assert.NoError(t, err)

	assert.Equal(t, 1, p.Version)
	assert.Equal(t, 1, len(p.Statement))

	assert.NotNil(t, p.Statement[0].Condition)
	assert.NotNil(t, p.Statement[0].Condition.AtLeastOne)
	assert.NotNil(t, p.Statement[0].Condition.AtLeastOne.StringIn)

	assert.Nil(t, p.Statement[0].Condition.MustHaveAll)
}

func TestParseJSON_No_AtLeastOne(t *testing.T) {
	strPolicy := `
	{
		"Version": 1,
		"PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		"Statement": [	
			{
				"Effect": "Allow",
				"Resource": "res:::leave",
				"Action": ["act:::leave:approve"],
				"Condition": {
					"MustHaveAll": {
						"StringIn": {
							"prop:::employee:employee_uuid": [
								"11111111",  
                            	"22222222",  
                            	"33333333",  
                            	"44444444" 
							]	
						}
					}
				}	
			}
		]
	}`
	p, err := ParseJSON([]byte(strPolicy))
	assert.NoError(t, err)

	assert.Equal(t, 1, p.Version)
	assert.Equal(t, 1, len(p.Statement))

	assert.NotNil(t, p.Statement[0].Condition)
	assert.NotNil(t, p.Statement[0].Condition.MustHaveAll)
	assert.NotNil(t, p.Statement[0].Condition.MustHaveAll.StringIn)

	assert.Nil(t, p.Statement[0].Condition.AtLeastOne)
}
