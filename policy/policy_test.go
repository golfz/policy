package policy

import (
	"github.com/mastertech-hq/authority/pkg/authority"
	"testing"
	"time"
)

// Adams is logging in
// Adams is requesting to approve leave request, which is owned by Bob, with id 1234
// POST: /api/v1/leave/request/1234/approve
// Can Adams approve leave request 1234?
// more info:
// Adams is Bob's manager

type Application struct {
	resource   string
	action     string
	properties Property
}

type Property struct {
	String  map[string]string
	Integer map[string]int
	Float   map[string]float64
	Bool    map[string]bool
}

type TimeRange struct {
	From time.Time
	To   time.Time
}

func TestIsValid(t *testing.T) {
	valid, err := authority.New(me, policy).IsValidApplication(Application{
		resource: "res:::leave",
		action:   "act:::leave:approve",
		properties: Property{
			String: map[string]string{
				"prop:::employee:employee_uuid":     employee_uuid,
				"prop:::employee:organization_uuid": employee_organization_uuid,
				"prop:::employee:company_uuid":      employee_company_uuid,
			},
		},
	})
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("expected valid to be true")
	}

	// do something you want to do
}
