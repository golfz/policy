package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_considerAvailableConditions(t *testing.T) {
	ac := AvailableCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop:::employee:employee_name": {"foo", "bar"},
			},
		},
	}

	res := Resource{
		Resource: "res:::employee",
		Action:   "act:::employee:read",
		Properties: Property{
			String: map[string]string{
				"prop:::employee:employee_name": "foo",
			},
		},
	}

	matched, total, err := considerAvailableConditions(ac, res)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerAvailableConditions_matched_2_from_3(t *testing.T) {
	ac := AvailableCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop:::employee:employee_name":     {"foo", "bar"},
				"prop:::employee:employee_org":      {"foo", "bar"},
				"prop:::employee:employee_position": {"foo", "bar"},
			},
		},
	}

	res := Resource{
		Resource: "res:::employee",
		Action:   "act:::employee:read",
		Properties: Property{
			String: map[string]string{
				"prop:::employee:employee_name":     "foo",
				"prop:::employee:employee_org":      "bar",
				"prop:::employee:employee_position": "no",
			},
		},
	}

	matched, total, err := considerAvailableConditions(ac, res)
	assert.NoError(t, err)
	assert.Equal(t, 2, matched)
	assert.Equal(t, 3, total)
}
