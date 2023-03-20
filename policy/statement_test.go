package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_convertEffectToBoolean(t *testing.T) {
	effect, err := convertEffectToBoolean("Allow")
	assert.NoError(t, err)
	assert.Equal(t, ALLOWED, effect)

	effect, err = convertEffectToBoolean("Deny")
	assert.NoError(t, err)
	assert.Equal(t, DENIED, effect)

	effect, err = convertEffectToBoolean("Invalid")
	assert.Error(t, err)
	assert.Equal(t, DENIED, effect)

	_, err = convertEffectToBoolean("")
	assert.Error(t, err)

	// Test case-insensitive
	_, err = convertEffectToBoolean("allow")
	assert.Error(t, err)

	// Test case-insensitive
	_, err = convertEffectToBoolean("deny")
	assert.Error(t, err)
}

func Test_considerAvailableConditions(t *testing.T) {
	ac := AvailableCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop:::employee:prop1": {"foo", "bar"},
			},
		},
	}

	res := Resource{
		Resource: "res:::employee",
		Action:   "act:::employee:read",
		Properties: Property{
			String: map[string]string{
				"prop:::employee:prop1": "foo",
			},
		},
	}

	matched, total, err := considerAvailableConditions(ac, res)
	assert.NoError(t, err)
	assert.Equal(t, 1, matched)
	assert.Equal(t, 1, total)
}

func Test_considerAvailableConditions_matched_12_from_20(t *testing.T) {
	ac := AvailableCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop:::employee:prop1": {"foo", "bar"},
				"prop:::employee:prop2": {"foo", "bar"},
				"prop:::employee:prop3": {"foo", "bar"},
			},
			StringEqual: map[string]string{
				"prop:::employee:prop4": "foo",
				"prop:::employee:prop5": "bar",
			},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn: map[string][]int{
				"prop:::employee:prop6": {1, 2, 3},
				"prop:::employee:prop7": {1, 2, 3},
				"prop:::employee:prop8": {1, 2, 3},
			},
			IntegerEqual: map[string]int{
				"prop:::employee:prop9":  1,
				"prop:::employee:prop10": 2,
			},
		},
		FloatCondition: FloatCondition{
			FloatIn: map[string][]float64{
				"prop:::employee:prop11": {1.1, 2.2, 3.3},
				"prop:::employee:prop12": {1.1, 2.2, 3.3},
				"prop:::employee:prop13": {1.1, 2.2, 3.3},
			},
			FloatEqual: map[string]float64{
				"prop:::employee:prop14": 1.1,
				"prop:::employee:prop15": 2.2,
			},
		},
		BoolCondition: BoolCondition{
			BooleanIn: map[string][]bool{
				"prop:::employee:prop16": {true},
				"prop:::employee:prop17": {true},
				"prop:::employee:prop18": {true},
			},
			BooleanEqual: map[string]bool{
				"prop:::employee:prop19": true,
				"prop:::employee:prop20": true,
			},
		},
	}

	res := Resource{
		Resource: "res:::employee",
		Action:   "act:::employee:read",
		Properties: Property{
			String: map[string]string{
				"prop:::employee:prop1": "foo", // matched
				"prop:::employee:prop2": "bar", // matched
				"prop:::employee:prop3": "no",  // not matched
				"prop:::employee:prop4": "foo", // matched
				"prop:::employee:prop5": "no",  // not matched
			},
			Integer: map[string]int{
				"prop:::employee:prop6":  1, // matched
				"prop:::employee:prop7":  2, // matched
				"prop:::employee:prop8":  0, // not matched
				"prop:::employee:prop9":  1, // matched
				"prop:::employee:prop10": 0, // not matched
			},
			Float: map[string]float64{
				"prop:::employee:prop11": 1.1, // matched
				"prop:::employee:prop12": 2.2, // matched
				"prop:::employee:prop13": 0.0, // not matched
				"prop:::employee:prop14": 1.1, // matched
				"prop:::employee:prop15": 0.0, // not matched
			},
			Boolean: map[string]bool{
				"prop:::employee:prop16": true,  // matched
				"prop:::employee:prop17": true,  // matched
				"prop:::employee:prop18": false, // not matched
				"prop:::employee:prop19": true,  // matched
				"prop:::employee:prop20": false, // not matched
			},
		},
	}

	matched, total, err := considerAvailableConditions(ac, res)
	assert.NoError(t, err)
	assert.Equal(t, 12, matched)
	assert.Equal(t, 20, total)
}

func Test_considerAvailableConditions_error_props_not_found(t *testing.T) {
	ac := AvailableCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop:::employee:prop1": {"foo", "bar"},
				"prop:::employee:prop2": {"foo", "bar"},
				"prop:::employee:prop3": {"foo", "bar"},
			},
			StringEqual: map[string]string{
				"prop:::employee:prop4": "foo",
				"prop:::employee:prop5": "bar",
			},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn: map[string][]int{
				"prop:::employee:prop6": {1, 2, 3},
				"prop:::employee:prop7": {1, 2, 3},
				"prop:::employee:prop8": {1, 2, 3},
			},
			IntegerEqual: map[string]int{
				"prop:::employee:prop9":  1,
				"prop:::employee:prop10": 2,
			},
		},
		FloatCondition: FloatCondition{
			FloatIn: map[string][]float64{
				"prop:::employee:prop11": {1.1, 2.2, 3.3},
				"prop:::employee:prop12": {1.1, 2.2, 3.3},
				"prop:::employee:prop13": {1.1, 2.2, 3.3},
			},
			FloatEqual: map[string]float64{
				"prop:::employee:prop14": 1.1,
				"prop:::employee:prop15": 2.2,
			},
		},
		BoolCondition: BoolCondition{
			BooleanIn: map[string][]bool{
				"prop:::employee:prop16": {true},
				"prop:::employee:prop17": {true},
				"prop:::employee:prop18": {true},
			},
			BooleanEqual: map[string]bool{
				"prop:::employee:prop19": true,
				"prop:::employee:prop20": true,
			},
		},
	}

	res := Resource{
		Resource: "res:::employee",
		Action:   "act:::employee:read",
		Properties: Property{
			String: map[string]string{
				"prop:::employee:prop1": "foo", // matched
				"prop:::employee:prop2": "bar", // matched
				"prop:::employee:prop3": "no",  // not matched
				"prop:::employee:prop4": "foo", // matched
				// "prop:::employee:prop5": "no",  // error
			},
			Integer: map[string]int{
				"prop:::employee:prop6": 1, // matched
				"prop:::employee:prop7": 2, // matched
				"prop:::employee:prop8": 0, // not matched
				"prop:::employee:prop9": 1, // matched
				// "prop:::employee:prop10": 0, // error
			},
			Float: map[string]float64{
				"prop:::employee:prop11": 1.1, // matched
				"prop:::employee:prop12": 2.2, // matched
				"prop:::employee:prop13": 0.0, // not matched
				"prop:::employee:prop14": 1.1, // matched
				// "prop:::employee:prop15": 0.0, // error
			},
			Boolean: map[string]bool{
				"prop:::employee:prop16": true,  // matched
				"prop:::employee:prop17": true,  // matched
				"prop:::employee:prop18": false, // not matched
				"prop:::employee:prop19": true,  // matched
				// "prop:::employee:prop20": false, // error
			},
		},
	}

	_, _, err := considerAvailableConditions(ac, res)
	assert.Error(t, err)
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

func Test_considerIn_string_error_props_not_found(t *testing.T) {
	cons := map[string][]string{
		"prop:::employee:prop1": {"foo", "bar"},
		"prop:::employee:prop2": {"foo", "bar"},
		"prop:::employee:prop3": {"foo", "bar"},
	}

	res := map[string]string{
		"prop:::employee:prop1": "foo",
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.Error(t, err)
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

func Test_considerIn_integer_error_props_not_found(t *testing.T) {
	cons := map[string][]int{
		"prop:::employee:prop1": {10, 20},
		"prop:::employee:prop2": {10, 20},
		"prop:::employee:prop3": {10, 20},
	}

	res := map[string]int{
		"prop:::employee:prop1": 10,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.Error(t, err)
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

func Test_considerIn_float_error_props_not_found(t *testing.T) {
	cons := map[string][]float64{
		"prop:::employee:prop1": {10.0, 20.0},
		"prop:::employee:prop2": {10.0, 20.0},
		"prop:::employee:prop3": {10.0, 20.0},
	}

	res := map[string]float64{
		"prop:::employee:prop1": 10.0,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.Error(t, err)
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

func Test_considerIn_boolean_error_props_not_found(t *testing.T) {
	cons := map[string][]bool{
		"prop:::employee:prop1": {true},
		"prop:::employee:prop2": {true},
		"prop:::employee:prop3": {true},
	}

	res := map[string]bool{
		"prop:::employee:prop1": true,
	}

	var matched, total int
	var err error

	considerIn(cons, res, &matched, &total, &err)
	assert.Error(t, err)
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

func Test_considerEqual_string_error_props_not_found(t *testing.T) {
	cons := map[string]string{
		"prop:::employee:prop1": "foo",
		"prop:::employee:prop2": "bar",
		"prop:::employee:prop3": "baz",
	}

	res := map[string]string{
		"prop:::employee:prop1": "foo",
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.Error(t, err)
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

func Test_considerEqual_int_error_props_not_found(t *testing.T) {
	cons := map[string]int{
		"prop:::employee:prop1": 10,
		"prop:::employee:prop2": 20,
		"prop:::employee:prop3": 30,
	}

	res := map[string]int{
		"prop:::employee:prop1": 10,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.Error(t, err)
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

func Test_considerEqual_float_error_props_not_found(t *testing.T) {
	cons := map[string]float64{
		"prop:::employee:prop1": 10.0,
		"prop:::employee:prop2": 20.0,
		"prop:::employee:prop3": 30.0,
	}

	res := map[string]float64{
		"prop:::employee:prop1": 10.0,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.Error(t, err)
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

func Test_considerEqual_bool_error_props_not_found(t *testing.T) {
	cons := map[string]bool{
		"prop:::employee:prop1": true,
		"prop:::employee:prop2": true,
		"prop:::employee:prop3": true,
	}

	res := map[string]bool{
		"prop:::employee:prop1": true,
	}

	var matched, total int
	var err error

	considerEqual(cons, res, &matched, &total, &err)
	assert.Error(t, err)
}
