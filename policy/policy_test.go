package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPolicy_IsAccessAllowed(t *testing.T) {

}

func TestPolicy_getStatementsForResource_found_1_from_1(t *testing.T) {
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

func TestPolicy_getStatementsForResource_found_2_from_3(t *testing.T) {
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
func TestPolicy_getStatementsForResource_found_only_1_matched_action(t *testing.T) {
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
func TestPolicy_getStatementsForResource_found_0_no_matched_action(t *testing.T) {
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

func TestPolicy_getStatementsForResource_found_0_no_matched_resource(t *testing.T) {
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

func TestPolicy_getStatementsForResource_found_0_no_statement(t *testing.T) {
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
