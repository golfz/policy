package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

//////////////////////////////////////////////////////////////////
//                  considerStatementConditions                 //
/////////////////////////////////////////////////////////////////

func Test_considerStatementConditions_AtLeastOneError_NotEnoughProperties_Expect_Error(t *testing.T) {
	condition := Condition{
		AtLeastOne: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop1": "value1",
					"prop:::something:prop2": "value2",
					"prop:::something:prop3": "value3",
				},
			},
		},
		MustHaveAll: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop4": "value4",
					"prop:::something:prop5": "value5",
				},
			},
		},
	}

	// removed prop3, so not enough properties
	res := Resource{
		Resource: "",
		Action:   "",
		Properties: Property{
			String: map[string]string{
				"prop:::something:prop1": "value1",
				"prop:::something:prop2": "value2",
				// "prop:::something:prop3": "value3", // removed
				"prop:::something:prop4": "value4",
				"prop:::something:prop5": "value5",
			},
		},
	}

	_, err := considerStatementConditions(condition, res)
	assert.Error(t, err)
}

func Test_considerStatementConditions_MustHaveAllError_NotEnoughProperties_Expect_Error(t *testing.T) {
	condition := Condition{
		AtLeastOne: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop1": "value1",
					"prop:::something:prop2": "value2",
					"prop:::something:prop3": "value3",
				},
			},
		},
		MustHaveAll: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop4": "value4",
					"prop:::something:prop5": "value5",
				},
			},
		},
	}

	// removed prop3, so not enough properties
	res := Resource{
		Resource: "",
		Action:   "",
		Properties: Property{
			String: map[string]string{
				"prop:::something:prop1": "value1",
				"prop:::something:prop2": "value2",
				"prop:::something:prop3": "value3",
				"prop:::something:prop4": "value4",
				// "prop:::something:prop5": "value5", // removed
			},
		},
	}

	_, err := considerStatementConditions(condition, res)
	assert.Error(t, err)
}

func Test_considerStatementConditions_NotMatched_AtLeastOne_and_NotMatched_MustHaveAll_Expect_NotMatched(t *testing.T) {
	condition := Condition{
		AtLeastOne: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop1": "value1",
					"prop:::something:prop2": "value2",
					"prop:::something:prop3": "value3",
				},
			},
		},
		MustHaveAll: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop4": "value4",
					"prop:::something:prop5": "value5",
				},
			},
		},
	}

	res := Resource{
		Resource: "",
		Action:   "",
		Properties: Property{
			String: map[string]string{
				"prop:::something:prop1": "no",
				"prop:::something:prop2": "no",
				"prop:::something:prop3": "no",
				"prop:::something:prop4": "value4",
				"prop:::something:prop5": "no",
			},
		},
	}

	isMatched, err := considerStatementConditions(condition, res)
	assert.NoError(t, err)
	assert.False(t, isMatched)
}

func Test_considerStatementConditions_Matched_AtLeastOne_and_NotMatched_MustHaveAll_Expect_NotMatched(t *testing.T) {
	condition := Condition{
		AtLeastOne: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop1": "value1",
					"prop:::something:prop2": "value2",
					"prop:::something:prop3": "value3",
				},
			},
		},
		MustHaveAll: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop4": "value4",
					"prop:::something:prop5": "value5",
				},
			},
		},
	}

	res := Resource{
		Resource: "",
		Action:   "",
		Properties: Property{
			String: map[string]string{
				"prop:::something:prop1": "value1",
				"prop:::something:prop2": "value2",
				"prop:::something:prop3": "value3",
				"prop:::something:prop4": "value4",
				"prop:::something:prop5": "no",
			},
		},
	}

	isMatched, err := considerStatementConditions(condition, res)
	assert.NoError(t, err)
	assert.False(t, isMatched)
}

func Test_considerStatementConditions_NotMatched_AtLeastOne_and_Matched_MustHaveAll_Expect_NotMatched(t *testing.T) {
	condition := Condition{
		AtLeastOne: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop1": "value1",
					"prop:::something:prop2": "value2",
					"prop:::something:prop3": "value3",
				},
			},
		},
		MustHaveAll: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop4": "value4",
					"prop:::something:prop5": "value5",
				},
			},
		},
	}

	res := Resource{
		Resource: "",
		Action:   "",
		Properties: Property{
			String: map[string]string{
				"prop:::something:prop1": "no",
				"prop:::something:prop2": "no",
				"prop:::something:prop3": "no",
				"prop:::something:prop4": "value4",
				"prop:::something:prop5": "value5",
			},
		},
	}

	isMatched, err := considerStatementConditions(condition, res)
	assert.NoError(t, err)
	assert.False(t, isMatched)
}

func Test_considerStatementConditions_Matched_AtLeastOne_and_Matched_MustHaveAll_Expect_Matched(t *testing.T) {
	condition := Condition{
		AtLeastOne: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop1": "value1",
					"prop:::something:prop2": "value2",
					"prop:::something:prop3": "value3",
				},
			},
		},
		MustHaveAll: &PropertyCondition{
			StringCondition: StringCondition{
				StringEqual: map[string]string{
					"prop:::something:prop4": "value4",
					"prop:::something:prop5": "value5",
				},
			},
		},
	}

	res := Resource{
		Resource: "",
		Action:   "",
		Properties: Property{
			String: map[string]string{
				"prop:::something:prop1": "value1",
				"prop:::something:prop2": "value2",
				"prop:::something:prop3": "value3",
				"prop:::something:prop4": "value4",
				"prop:::something:prop5": "value5",
			},
		},
	}

	isMatched, err := considerStatementConditions(condition, res)
	assert.NoError(t, err)
	assert.True(t, isMatched)
}

////////////////////////////////////////////////////////////////////
//               convertEffectStringToResultEffect                //
////////////////////////////////////////////////////////////////////

func Test_convertEffectStringToResultEffect(t *testing.T) {
	effect, err := convertEffectStringToResultEffect("Allow")
	assert.NoError(t, err)
	assert.Equal(t, ALLOWED, effect)

	effect, err = convertEffectStringToResultEffect("Deny")
	assert.NoError(t, err)
	assert.Equal(t, DENIED, effect)

	effect, err = convertEffectStringToResultEffect("Invalid")
	assert.Error(t, err)
	assert.Equal(t, DENIED, effect)

	_, err = convertEffectStringToResultEffect("")
	assert.Error(t, err)

	// Test case-insensitive
	_, err = convertEffectStringToResultEffect("allow")
	assert.Error(t, err)

	// Test case-insensitive
	_, err = convertEffectStringToResultEffect("deny")
	assert.Error(t, err)
}
