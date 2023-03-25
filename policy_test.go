package policy

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

////////////////////////////////////////////////////////////////////
//                    getStatementsForResource                    //
////////////////////////////////////////////////////////////////////

func TestPolicy_IsAccessAllowed_Error(t *testing.T) {
	p := Policy{
		Error: errors.New("error"),
	}

	_, err := p.IsAccessAllowed(Resource{})
	assert.Error(t, err)
}

func Test_IsAccessAllowed_No_Statement_Found_Expect_Denied(t *testing.T) {
	p := Policy{
		Version:  1,
		PolicyID: "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		Statement: []Statement{
			{
				Effect:   "Allow",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
					"act:::something:action2",
				},
				Condition: nil,
			},
		},
	}

	res := Resource{
		Resource:   "res:::something",
		Action:     "act:::something:action3",
		Properties: Property{},
	}

	result, err := p.IsAccessAllowed(res)
	assert.NoError(t, err)
	assert.Equal(t, DENIED, result)
}

func Test_IsAccessAllowed_Invalid_Effect_Statement_Expect_Error(t *testing.T) {
	p := Policy{
		Version:  1,
		PolicyID: "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		Statement: []Statement{
			{
				Effect:   "Invalid",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: nil,
			},
			{
				Effect:   "Allow",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: nil,
			},
			{
				Effect:   "Deny",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: nil,
			},
		},
	}

	res := Resource{
		Resource:   "res:::something",
		Action:     "act:::something:action1",
		Properties: Property{},
	}

	_, err := p.IsAccessAllowed(res)
	assert.Error(t, err)
	fmt.Println(err)
}

func Test_IsAccessAllowed_Only_1_Deny_Although_have_multi_Allow_Expect_Denied(t *testing.T) {
	p := Policy{
		Version:  1,
		PolicyID: "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		Statement: []Statement{
			{
				Effect:   "Deny",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: nil,
			},
			{
				Effect:   "Allow",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: nil,
			},
			{
				Effect:   "Allow",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: nil,
			},
		},
	}

	res := Resource{
		Resource:   "res:::something",
		Action:     "act:::something:action1",
		Properties: Property{},
	}

	result, err := p.IsAccessAllowed(res)
	assert.NoError(t, err)
	assert.Equal(t, DENIED, result)
}

func Test_IsAccessAllowed_No_Deny_with_1_Allow_Expect_Allowed(t *testing.T) {
	p := Policy{
		Version:  1,
		PolicyID: "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		Statement: []Statement{
			{
				Effect:   "Deny",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: &Condition{
					MustHaveAll: &PropertyCondition{
						StringCondition: StringCondition{
							StringEqual: map[string]string{
								"prop:::something:prop1": "value1",
							},
						},
					},
				},
			},
			{
				Effect:   "Deny",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: &Condition{
					MustHaveAll: &PropertyCondition{
						StringCondition: StringCondition{
							StringEqual: map[string]string{
								"prop:::something:prop2": "value2",
							},
						},
					},
				},
			},
			{
				Effect:   "Allow",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: &Condition{
					MustHaveAll: &PropertyCondition{
						StringCondition: StringCondition{
							StringEqual: map[string]string{
								"prop:::something:prop3": "value3",
							},
						},
					},
				},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:action1",
		Properties: Property{
			String: map[string]string{
				"prop:::something:prop1": "no",
				"prop:::something:prop2": "no",
				"prop:::something:prop3": "value3",
			},
		},
	}

	result, err := p.IsAccessAllowed(res)
	assert.NoError(t, err)
	assert.Equal(t, ALLOWED, result)
}

func Test_IsAccessAllowed_No_Matched_Statement_Expect_Denied(t *testing.T) {
	p := Policy{
		Version:  1,
		PolicyID: "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		Statement: []Statement{
			{
				Effect:   "Deny",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: &Condition{
					MustHaveAll: &PropertyCondition{
						StringCondition: StringCondition{
							StringEqual: map[string]string{
								"prop:::something:prop1": "value1",
							},
						},
					},
				},
			},
			{
				Effect:   "Deny",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: &Condition{
					MustHaveAll: &PropertyCondition{
						StringCondition: StringCondition{
							StringEqual: map[string]string{
								"prop:::something:prop2": "value2",
							},
						},
					},
				},
			},
			{
				Effect:   "Allow",
				Resource: "res:::something",
				Action: []string{
					"act:::something:action1",
				},
				Condition: &Condition{
					MustHaveAll: &PropertyCondition{
						StringCondition: StringCondition{
							StringEqual: map[string]string{
								"prop:::something:prop3": "value3",
							},
						},
					},
				},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:action1",
		Properties: Property{
			String: map[string]string{
				"prop:::something:prop1": "no",
				"prop:::something:prop2": "no",
				"prop:::something:prop3": "no",
			},
		},
	}

	result, err := p.IsAccessAllowed(res)
	assert.NoError(t, err)
	assert.Equal(t, DENIED, result)
}

////////////////////////////////////////////////////////////////////
//                    getStatementsForResource                    //
////////////////////////////////////////////////////////////////////

func Test_getStatementsForResource_found_1_from_1(t *testing.T) {
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
				]
			}
		]
	}`
	p, err := ParseJSON([]byte(strPolicy))
	assert.NoError(t, err)

	res := Resource{
		Resource: "res:::leave",
		Action:   "act:::leave:approve",
	}

	statements := p.getStatementsForResource(res)
	assert.Equal(t, 1, len(statements))
}

func Test_getStatementsForResource_found_2_from_3(t *testing.T) {
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
				]
			},
			{
				"Effect": "Deny",
				"Resource": "res:::leave",
				"Action": [
					"act:::leave:approve"
				]
			},
			{
				"Effect": "Allow",
				"Resource": "res:::employee",
				"Action": [
					"act:::employee:delete"
				]
			}
		]
	}`
	p, err := ParseJSON([]byte(strPolicy))
	assert.NoError(t, err)

	res := Resource{
		Resource: "res:::leave",
		Action:   "act:::leave:approve",
	}

	statements := p.getStatementsForResource(res)
	assert.Equal(t, 2, len(statements))
}

// this test case is to test the case when there are 2 statements with same resource
// but only 1 statement with action
func Test_getStatementsForResource_found_only_1_matched_action(t *testing.T) {
	// policy have 2 statements with resource "res:::leave"
	// but only 1 statement with action "act:::leave:approve"
	jsonPolicy := `
	{
		"Version": 1,
		"PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		"Statement": [	
			{
				"Effect": "Allow",
				"Resource": "res:::leave",
				"Action": [
					"act:::leave:approve"
				]
			},
			{
				"Effect": "Deny",
				"Resource": "res:::leave",
				"Action": [
					"act:::leave:create"
				]
			},
			{
				"Effect": "Allow",
				"Resource": "res:::employee",
				"Action": [
					"act:::employee:delete"
				]
			}
		]
	}`
	p, err := ParseJSON([]byte(jsonPolicy))
	assert.NoError(t, err)

	res := Resource{
		Resource: "res:::leave",
		Action:   "act:::leave:approve",
	}

	statements := p.getStatementsForResource(res)
	assert.Equal(t, 1, len(statements))
}

// this test case is to test the case when there are 2 statements with same resource
// but no statement with expected action
func Test_getStatementsForResource_found_0_no_matched_action(t *testing.T) {
	// policy have 2 statements with resource "res:::leave"
	// but no statement with action "act:::leave:approve"
	jsonPolicy := `
	{
		"Version": 1,
		"PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		"Statement": [	
			{
				"Effect": "Allow",
				"Resource": "res:::leave",
				"Action": [
					"act:::leave:read"
				]
			},
			{
				"Effect": "Deny",
				"Resource": "res:::leave",
				"Action": [
					"act:::leave:create"
				]
			},
			{
				"Effect": "Allow",
				"Resource": "res:::employee",
				"Action": [
					"act:::employee:delete"
				]
			}
		]
	}`
	p, err := ParseJSON([]byte(jsonPolicy))
	assert.NoError(t, err)

	res := Resource{
		Resource: "res:::leave",
		Action:   "act:::leave:approve",
	}

	statements := p.getStatementsForResource(res)
	assert.Equal(t, 0, len(statements))
}

func Test_getStatementsForResource_found_0_no_matched_resource(t *testing.T) {
	jsonPolicy := `
	{
		"Version": 1,
		"PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		"Statement": [	
			{
				"Effect": "Allow",
				"Resource": "res:::leave",
				"Action": [
					"act:::leave:read"
				]
			},
			{
				"Effect": "Deny",
				"Resource": "res:::leave",
				"Action": [
					"act:::leave:create"
				]
			},
			{
				"Effect": "Allow",
				"Resource": "res:::employee",
				"Action": [
					"act:::employee:delete"
				]
			}
		]
	}`
	p, err := ParseJSON([]byte(jsonPolicy))
	assert.NoError(t, err)

	res := Resource{
		Resource: "res:::unknown",
		Action:   "act:::unknown:read",
	}

	statements := p.getStatementsForResource(res)
	assert.Equal(t, 0, len(statements))
}

func Test_getStatementsForResource_found_0_no_statement(t *testing.T) {
	jsonPolicy := `
	{
		"Version": 1,
		"PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
		"Statement": []
	}`
	p, err := ParseJSON([]byte(jsonPolicy))
	assert.NoError(t, err)

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
	}

	statements := p.getStatementsForResource(res)
	assert.Equal(t, 0, len(statements))
}
