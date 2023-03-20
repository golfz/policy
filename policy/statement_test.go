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

/* /////////////////////////////////////////////////////////////////
//                         considerIn                             //
///////////////////////////////////////////////////////////////// */

// ----------------------- string ---------------------------------

func Test_considerIn_string_matched_1_from_1(t *testing.T) {
	cons := map[string][]string{
		"prop:::employee:employee_name": {"foo", "bar"},
	}

	res := map[string]string{
		"prop:::employee:employee_name": "foo",
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerIn_string_matched_2_from_3(t *testing.T) {
	cons := map[string][]string{
		"prop:::employee:employee_name":     {"foo", "bar"},
		"prop:::employee:employee_org":      {"foo", "bar"},
		"prop:::employee:employee_position": {"foo", "bar"},
	}

	res := map[string]string{
		"prop:::employee:employee_name":     "foo",
		"prop:::employee:employee_org":      "bar",
		"prop:::employee:employee_position": "no",
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 2, matched)
	assert.Equal(t, 3, total)
}

func Test_considerIn_string_matched_0(t *testing.T) {
	cons := map[string][]string{
		"prop:::employee:employee_name":     {"foo", "bar"},
		"prop:::employee:employee_org":      {"foo", "bar"},
		"prop:::employee:employee_position": {"foo", "bar"},
	}

	res := map[string]string{
		"prop:::employee:employee_name":     "no",
		"prop:::employee:employee_org":      "no",
		"prop:::employee:employee_position": "no",
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 0, matched)
	assert.Equal(t, 3, total)
}

// ----------------------- integer ---------------------------------

func Test_considerIn_integer_matched_1_from_1(t *testing.T) {
	cons := map[string][]int{
		"prop:::employee:employee_age": {10, 20},
	}

	res := map[string]int{
		"prop:::employee:employee_age": 10,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerIn_integer_matched_2_from_3(t *testing.T) {
	cons := map[string][]int{
		"prop:::employee:employee_age":        {10, 20},
		"prop:::employee:employee_experience": {10, 20},
		"prop:::employee:employee_salary":     {10, 20},
	}

	res := map[string]int{
		"prop:::employee:employee_age":        10,
		"prop:::employee:employee_experience": 20,
		"prop:::employee:employee_salary":     0,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 2, matched)
	assert.Equal(t, 3, total)
}

func Test_considerIn_integer_matched_0(t *testing.T) {
	cons := map[string][]int{
		"prop:::employee:employee_age":        {10, 20},
		"prop:::employee:employee_experience": {10, 20},
		"prop:::employee:employee_salary":     {10, 20},
	}

	res := map[string]int{
		"prop:::employee:employee_age":        0,
		"prop:::employee:employee_experience": 0,
		"prop:::employee:employee_salary":     0,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 0, matched)
	assert.Equal(t, 3, total)
}

// ----------------------- float ---------------------------------

func Test_considerIn_float_matched_1_from_1(t *testing.T) {
	cons := map[string][]float64{
		"prop:::employee:employee_age": {10.0, 20.0},
	}

	res := map[string]float64{
		"prop:::employee:employee_age": 10.0,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerIn_float_matched_2_from_3(t *testing.T) {
	cons := map[string][]float64{
		"prop:::employee:employee_age":        {10.0, 20.0},
		"prop:::employee:employee_experience": {10.0, 20.0},
		"prop:::employee:employee_salary":     {10.0, 20.0},
	}

	res := map[string]float64{
		"prop:::employee:employee_age":        10.0,
		"prop:::employee:employee_experience": 20.0,
		"prop:::employee:employee_salary":     0.0,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 2, matched)
	assert.Equal(t, 3, total)
}

func Test_considerIn_float_matched_0(t *testing.T) {
	cons := map[string][]float64{
		"prop:::employee:employee_age":        {10.0, 20.0},
		"prop:::employee:employee_experience": {10.0, 20.0},
		"prop:::employee:employee_salary":     {10.0, 20.0},
	}

	res := map[string]float64{
		"prop:::employee:employee_age":        0.0,
		"prop:::employee:employee_experience": 0.0,
		"prop:::employee:employee_salary":     0.0,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 0, matched)
	assert.Equal(t, 3, total)
}

// ----------------------- boolean ---------------------------------

func Test_considerIn_boolean_matched_1_from_1(t *testing.T) {
	cons := map[string][]bool{
		"prop:::employee:employee_active": {true},
	}

	res := map[string]bool{
		"prop:::employee:employee_active": true,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerIn_boolean_matched_2_from_3(t *testing.T) {
	cons := map[string][]bool{
		"prop:::employee:employee_active":     {true},
		"prop:::employee:employee_experience": {true},
		"prop:::employee:employee_salary":     {true},
	}

	res := map[string]bool{
		"prop:::employee:employee_active":     true,
		"prop:::employee:employee_experience": true,
		"prop:::employee:employee_salary":     false,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 2, matched)
	assert.Equal(t, 3, total)
}

func Test_considerIn_boolean_matched_0(t *testing.T) {
	cons := map[string][]bool{
		"prop:::employee:employee_active":     {true},
		"prop:::employee:employee_experience": {true},
		"prop:::employee:employee_salary":     {true},
	}

	res := map[string]bool{
		"prop:::employee:employee_active":     false,
		"prop:::employee:employee_experience": false,
		"prop:::employee:employee_salary":     false,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 0, matched)
	assert.Equal(t, 3, total)
}
