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
		"prop:::employee:prop1": {"foo", "bar"},
	}

	res := map[string]string{
		"prop:::employee:prop1": "foo",
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
		"prop:::employee:prop1": {"foo", "bar"},
		"prop:::employee:prop2": {"foo", "bar"},
		"prop:::employee:prop3": {"foo", "bar"},
	}

	res := map[string]string{
		"prop:::employee:prop1": "foo",
		"prop:::employee:prop2": "bar",
		"prop:::employee:prop3": "no",
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
		"prop:::employee:prop1": {"foo", "bar"},
		"prop:::employee:prop2": {"foo", "bar"},
		"prop:::employee:prop3": {"foo", "bar"},
	}

	res := map[string]string{
		"prop:::employee:prop1": "no",
		"prop:::employee:prop2": "no",
		"prop:::employee:prop3": "no",
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
		"prop:::employee:prop1": {10, 20},
	}

	res := map[string]int{
		"prop:::employee:prop1": 10,
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
		"prop:::employee:prop1": {10, 20},
		"prop:::employee:prop2": {10, 20},
		"prop:::employee:prop3": {10, 20},
	}

	res := map[string]int{
		"prop:::employee:prop1": 10,
		"prop:::employee:prop2": 20,
		"prop:::employee:prop3": 0,
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
		"prop:::employee:prop1": {10, 20},
		"prop:::employee:prop2": {10, 20},
		"prop:::employee:prop3": {10, 20},
	}

	res := map[string]int{
		"prop:::employee:prop1": 0,
		"prop:::employee:prop2": 0,
		"prop:::employee:prop3": 0,
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
		"prop:::employee:prop1": {10.0, 20.0},
	}

	res := map[string]float64{
		"prop:::employee:prop1": 10.0,
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
		"prop:::employee:prop1": {10.0, 20.0},
		"prop:::employee:prop2": {10.0, 20.0},
		"prop:::employee:prop3": {10.0, 20.0},
	}

	res := map[string]float64{
		"prop:::employee:prop1": 10.0,
		"prop:::employee:prop2": 20.0,
		"prop:::employee:prop3": 0.0,
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
		"prop:::employee:prop1": {10.0, 20.0},
		"prop:::employee:prop2": {10.0, 20.0},
		"prop:::employee:prop3": {10.0, 20.0},
	}

	res := map[string]float64{
		"prop:::employee:prop1": 0.0,
		"prop:::employee:prop2": 0.0,
		"prop:::employee:prop3": 0.0,
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
		"prop:::employee:prop1": {true},
	}

	res := map[string]bool{
		"prop:::employee:prop1": true,
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
		"prop:::employee:prop1": {true},
		"prop:::employee:prop2": {true},
		"prop:::employee:prop3": {true},
	}

	res := map[string]bool{
		"prop:::employee:prop1": true,
		"prop:::employee:prop2": true,
		"prop:::employee:prop3": false,
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
		"prop:::employee:prop1": {true},
		"prop:::employee:prop2": {true},
		"prop:::employee:prop3": {true},
	}

	res := map[string]bool{
		"prop:::employee:prop1": false,
		"prop:::employee:prop2": false,
		"prop:::employee:prop3": false,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 0, matched)
	assert.Equal(t, 3, total)
}

/* /////////////////////////////////////////////////////////////////
//                         considerEqual						  //
///////////////////////////////////////////////////////////////// */

// ----------------------- string ---------------------------------

func Test_considerEqual_string_matched_1_from_1(t *testing.T) {
	cons := map[string]string{
		"prop:::employee:prop1": "foo",
	}

	res := map[string]string{
		"prop:::employee:prop1": "foo",
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerEqual_string_matched_2_from_3(t *testing.T) {
	cons := map[string]string{
		"prop:::employee:prop1": "foo",
		"prop:::employee:prop2": "bar",
		"prop:::employee:prop3": "baz",
	}

	res := map[string]string{
		"prop:::employee:prop1": "foo",
		"prop:::employee:prop2": "bar",
		"prop:::employee:prop3": "no",
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 2, matched)
	assert.Equal(t, 3, total)
}

func Test_considerEqual_string_matched_0(t *testing.T) {
	cons := map[string]string{
		"prop:::employee:prop1": "foo",
		"prop:::employee:prop2": "bar",
		"prop:::employee:prop3": "baz",
	}

	res := map[string]string{
		"prop:::employee:prop1": "no",
		"prop:::employee:prop2": "no",
		"prop:::employee:prop3": "no",
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 0, matched)
	assert.Equal(t, 3, total)
}

// ----------------------- int ---------------------------------

func Test_considerEqual_int_matched_1_from_1(t *testing.T) {
	cons := map[string]int{
		"prop:::employee:prop1": 10,
	}

	res := map[string]int{
		"prop:::employee:prop1": 10,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerEqual_int_matched_2_from_3(t *testing.T) {
	cons := map[string]int{
		"prop:::employee:prop1": 10,
		"prop:::employee:prop2": 20,
		"prop:::employee:prop3": 30,
	}

	res := map[string]int{
		"prop:::employee:prop1": 10,
		"prop:::employee:prop2": 20,
		"prop:::employee:prop3": 0,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 2, matched)
	assert.Equal(t, 3, total)
}

func Test_considerEqual_int_matched_0(t *testing.T) {
	cons := map[string]int{
		"prop:::employee:prop1": 10,
		"prop:::employee:prop2": 20,
		"prop:::employee:prop3": 30,
	}

	res := map[string]int{
		"prop:::employee:prop1": 0,
		"prop:::employee:prop2": 0,
		"prop:::employee:prop3": 0,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 0, matched)
	assert.Equal(t, 3, total)
}

// ----------------------- float ---------------------------------

func Test_considerEqual_float_matched_1_from_1(t *testing.T) {
	cons := map[string]float64{
		"prop:::employee:prop1": 10.0,
	}

	res := map[string]float64{
		"prop:::employee:prop1": 10.0,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerEqual_float_matched_2_from_3(t *testing.T) {
	cons := map[string]float64{
		"prop:::employee:prop1": 10.0,
		"prop:::employee:prop2": 20.0,
		"prop:::employee:prop3": 30.0,
	}

	res := map[string]float64{
		"prop:::employee:prop1": 10.0,
		"prop:::employee:prop2": 20.0,
		"prop:::employee:prop3": 0.0,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 2, matched)
	assert.Equal(t, 3, total)
}

func Test_considerEqual_float_matched_0(t *testing.T) {
	cons := map[string]float64{
		"prop:::employee:prop1": 10.0,
		"prop:::employee:prop2": 20.0,
		"prop:::employee:prop3": 30.0,
	}

	res := map[string]float64{
		"prop:::employee:prop1": 0.0,
		"prop:::employee:prop2": 0.0,
		"prop:::employee:prop3": 0.0,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 0, matched)
	assert.Equal(t, 3, total)
}

// ----------------------- bool ---------------------------------

func Test_considerEqual_bool_matched_1_from_1(t *testing.T) {
	cons := map[string]bool{
		"prop:::employee:prop1": true,
	}

	res := map[string]bool{
		"prop:::employee:prop1": true,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerEqual_bool_matched_2_from_3(t *testing.T) {
	cons := map[string]bool{
		"prop:::employee:prop1": true,
		"prop:::employee:prop2": true,
		"prop:::employee:prop3": true,
	}

	res := map[string]bool{
		"prop:::employee:prop1": true,
		"prop:::employee:prop2": true,
		"prop:::employee:prop3": false,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 2, matched)
	assert.Equal(t, 3, total)
}

func Test_considerEqual_bool_matched_0(t *testing.T) {
	cons := map[string]bool{
		"prop:::employee:prop1": true,
		"prop:::employee:prop2": true,
		"prop:::employee:prop3": true,
	}

	res := map[string]bool{
		"prop:::employee:prop1": false,
		"prop:::employee:prop2": false,
		"prop:::employee:prop3": false,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.NoError(t, err)
	assert.Equal(t, 0, matched)
	assert.Equal(t, 3, total)
}
