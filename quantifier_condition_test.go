package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

/* /////////////////////////////////////////////////////////////////
//                  considerAtLeastOneCondition                   //
///////////////////////////////////////////////////////////////// */

func Test_considerAtLeastOneCondition_NilConditions_Expect_AlwaysMatched(t *testing.T) {
	// nil conditions, no resource properties, always matched
	res := Resource{}
	isMatched, err := considerAtLeastOneCondition(nil, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)

	// nil conditions, with resource properties, always matched
	res = Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1",
			},
		},
	}
	isMatched, err = considerAtLeastOneCondition(nil, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)
}

func Test_considerAtLeastOneCondition_Error_NotEnoughProperty_Expect_Error(t *testing.T) {
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop::something:prop1": {"value1", "value2"},
				"prop::something:prop2": {"value1", "value2"},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1",
			},
		},
	}

	_, err := considerAtLeastOneCondition(conditions, res)
	assert.Error(t, err)
}

func Test_considerAtLeastOneCondition_0_Conditions_Expect_AlwaysMatched(t *testing.T) {
	// all conditions are empty
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn:    map[string][]string{},
			StringEqual: map[string]string{},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn:    map[string][]int{},
			IntegerEqual: map[string]int{},
		},
		FloatCondition: FloatCondition{
			FloatIn:    map[string][]float64{},
			FloatEqual: map[string]float64{},
		},
		BooleanCondition: BooleanCondition{
			BooleanEqual: map[string]bool{},
			BooleanIn:    map[string][]bool{},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1",
			},
		},
	}

	isMatched, err := considerAtLeastOneCondition(conditions, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)
}

func Test_considerAtLeastOneCondition_Matched_only_1_conditions_Expect_Matched(t *testing.T) {
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop::something:prop1": {"value1", "value2"},
				"prop::something:prop2": {"value1", "value2"},
			},
			StringEqual: map[string]string{
				"prop::something:prop3": "value1",
			},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn: map[string][]int{
				"prop::something:prop4": {1, 2},
				"prop::something:prop5": {1, 2},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1", // matched
				"prop::something:prop2": "no",     // not matched
				"prop::something:prop3": "no",     // not matched
			},
			Integer: map[string]int{
				"prop::something:prop4": 0, // not matched
				"prop::something:prop5": 0, // not matched
			},
		},
	}

	isMatched, err := considerAtLeastOneCondition(conditions, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)
}

func Test_considerAtLeastOneCondition_Matched_All_Conditions_Expect_Matched(t *testing.T) {
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop::something:prop1": {"value1", "value2"},
				"prop::something:prop2": {"value1", "value2"},
			},
			StringEqual: map[string]string{
				"prop::something:prop3": "value1",
			},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn: map[string][]int{
				"prop::something:prop4": {1, 2},
				"prop::something:prop5": {1, 2},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1", // matched
				"prop::something:prop2": "value1", // matched
				"prop::something:prop3": "value1", // matched
			},
			Integer: map[string]int{
				"prop::something:prop4": 1, // matched
				"prop::something:prop5": 1, // matched
			},
		},
	}

	isMatched, err := considerAtLeastOneCondition(conditions, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)
}

func Test_considerAtLeastOneCondition_No_Matched_Conditions_Expect_NotMatched(t *testing.T) {
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop::something:prop1": {"value1", "value2"},
				"prop::something:prop2": {"value1", "value2"},
			},
			StringEqual: map[string]string{
				"prop::something:prop3": "value1",
			},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn: map[string][]int{
				"prop::something:prop4": {1, 2},
				"prop::something:prop5": {1, 2},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "no", // not matched
				"prop::something:prop2": "no", // not matched
				"prop::something:prop3": "no", // not matched
			},
			Integer: map[string]int{
				"prop::something:prop4": 0, //  not matched
				"prop::something:prop5": 0, //  not matched
			},
		},
	}

	isMatched, err := considerAtLeastOneCondition(conditions, res)
	assert.NoError(t, err)
	assert.False(t, isMatched)
}

/* /////////////////////////////////////////////////////////////////
//                  considerMustHaveAllCondition                  //
///////////////////////////////////////////////////////////////// */

func Test_considerMustHaveAllCondition_NilConditions_Expect_AlwaysMatched(t *testing.T) {
	// nil conditions, no resource properties, always matched
	res := Resource{}
	isMatched, err := considerMustHaveAllCondition(nil, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)

	// nil conditions, with resource properties, always matched
	res = Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1",
			},
		},
	}
	isMatched, err = considerMustHaveAllCondition(nil, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)
}

func Test_considerMustHaveAllCondition_Error_NotEnoughProperty_Expect_Error(t *testing.T) {
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop::something:prop1": {"value1", "value2"},
				"prop::something:prop2": {"value1", "value2"},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1",
			},
		},
	}

	_, err := considerMustHaveAllCondition(conditions, res)
	assert.Error(t, err)
}

func Test_considerMustHaveAllCondition_0_Conditions_Expect_AlwaysMatched(t *testing.T) {
	// all conditions are empty
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn:    map[string][]string{},
			StringEqual: map[string]string{},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn:    map[string][]int{},
			IntegerEqual: map[string]int{},
		},
		FloatCondition: FloatCondition{
			FloatIn:    map[string][]float64{},
			FloatEqual: map[string]float64{},
		},
		BooleanCondition: BooleanCondition{
			BooleanEqual: map[string]bool{},
			BooleanIn:    map[string][]bool{},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1",
			},
		},
	}

	isMatched, err := considerMustHaveAllCondition(conditions, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)
}

func Test_considerMustHaveAllCondition_Matched_only_1_conditions_Expect_NotMatched(t *testing.T) {
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop::something:prop1": {"value1", "value2"},
				"prop::something:prop2": {"value1", "value2"},
			},
			StringEqual: map[string]string{
				"prop::something:prop3": "value1",
			},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn: map[string][]int{
				"prop::something:prop4": {1, 2},
				"prop::something:prop5": {1, 2},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1", // matched
				"prop::something:prop2": "no",     // not matched
				"prop::something:prop3": "no",     // not matched
			},
			Integer: map[string]int{
				"prop::something:prop4": 0, // not matched
				"prop::something:prop5": 0, // not matched
			},
		},
	}

	isMatched, err := considerMustHaveAllCondition(conditions, res)
	assert.NoError(t, err)
	assert.False(t, isMatched)
}

func Test_considerMustHaveAllCondition_Matched_All_Conditions_Expect_Matched(t *testing.T) {
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop::something:prop1": {"value1", "value2"},
				"prop::something:prop2": {"value1", "value2"},
			},
			StringEqual: map[string]string{
				"prop::something:prop3": "value1",
			},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn: map[string][]int{
				"prop::something:prop4": {1, 2},
				"prop::something:prop5": {1, 2},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "value1", // matched
				"prop::something:prop2": "value1", // matched
				"prop::something:prop3": "value1", // matched
			},
			Integer: map[string]int{
				"prop::something:prop4": 1, // matched
				"prop::something:prop5": 1, // matched
			},
		},
	}

	isMatched, err := considerMustHaveAllCondition(conditions, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)
}

func Test_considerMustHaveAllCondition_No_Matched_Conditions_Expect_NotMatched(t *testing.T) {
	conditions := &PropertyCondition{
		StringCondition: StringCondition{
			StringIn: map[string][]string{
				"prop::something:prop1": {"value1", "value2"},
				"prop::something:prop2": {"value1", "value2"},
			},
			StringEqual: map[string]string{
				"prop::something:prop3": "value1",
			},
		},
		IntegerCondition: IntegerCondition{
			IntegerIn: map[string][]int{
				"prop::something:prop4": {1, 2},
				"prop::something:prop5": {1, 2},
			},
		},
	}

	res := Resource{
		Resource: "res:::something",
		Action:   "act:::something:read",
		Properties: Property{
			String: map[string]string{
				"prop::something:prop1": "no", // not matched
				"prop::something:prop2": "no", // not matched
				"prop::something:prop3": "no", // not matched
			},
			Integer: map[string]int{
				"prop::something:prop4": 0, //  not matched
				"prop::something:prop5": 0, //  not matched
			},
		},
	}

	isMatched, err := considerMustHaveAllCondition(conditions, res)
	assert.NoError(t, err)
	assert.False(t, isMatched)
}
