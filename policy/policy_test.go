package policy

import (
	"github.com/mastertech-hq/authority/pkg/authority"
	"testing"
)

// Adams is logging in
// Adams is requesting to approve leave request, which is owned by Bob, with id 1234
// POST: /api/v1/leave/request/1234/approve
// Can Adams approve leave request 1234?
// more info:
// Adams is Bob's manager

type Application struct {
	action    string
	resource  string
	condition map[string]string
}

func TestIsValid(t *testing.T) {
	me := ""
	policy := ""
	employee_uuid := "d89b9e25-b0f0-4056-86f0-c104007d1955"
	authority.On(me, policy).Consider(Application{
		action:   "approve",
		resource: "leave_request",
		condition: map[string]string{
			"res::company:employee:employee_uuid": employee_uuid,
		},
	})
}
