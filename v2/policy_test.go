package policy

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

type MockUserGetter struct {
	UserValue   map[string]string
	WasCalled   bool
	WhatIsParam string
}

func (mock *MockUserGetter) GetUserProperty(key string) string {
	mock.WasCalled = true
	mock.WhatIsParam = key
	return mock.UserValue[key]
}

type MockValidationOverrider struct {
	Result    bool
	Error     error
	WasCalled bool
}

func (mock *MockValidationOverrider) OverridePolicyValidation(policies []Policy, UserPropertyGetter UserPropertyGetter, res Resource) (bool, error) {
	mock.WasCalled = true
	return mock.Result, mock.Error
}

func TestIsAccessAllowed(t *testing.T) {
	t.Run("policyValidator with Error, expect error", func(t *testing.T) {
		// Arrange
		ctrl := policyValidator{Err: errors.New("error")}

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if result != DENIED {
			t.Errorf("want DENIED, but got %v", result)
		}
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("policyValidator with invalid effect, expect error", func(t *testing.T) {
		// Arrange
		ctrl := policyValidator{
			Policies: []Policy{
				{
					Statements: []Statement{
						{Effect: "Invalid Effect"},
					},
				},
			},
		}

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if result != DENIED {
			t.Errorf("want DENIED, but got %v", result)
		}
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("no matching resource, expect DENIED", func(t *testing.T) {
		// Arrange
		ctrl := policyValidator{
			Policies: []Policy{
				{
					Statements: []Statement{
						{
							Resource: "resource1",
							Effect:   statementEffectAllow,
						},
					},
				},
			},
		}
		ctrl.SetResource("resource2")
		want := DENIED

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if result != want {
			t.Errorf("want %v, but got %v", want, result)
		}
		if err != nil {
			t.Errorf("want nil, but got %v", err)
		}
	})

	t.Run("no matching Action, expect DENIED", func(t *testing.T) {
		// Arrange
		ctrl := policyValidator{
			Policies: []Policy{
				{
					Statements: []Statement{
						{
							Resource: "resource1",
							Actions:  []string{"action1", "action2"},
							Effect:   statementEffectAllow,
						},
					},
				},
			},
		}
		ctrl.SetResource("resource1")
		ctrl.SetAction("action3")
		want := DENIED

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if result != want {
			t.Errorf("want %v, but got %v", want, result)
		}
		if err != nil {
			t.Errorf("want nil, but got %v", err)
		}
	})

	t.Run("matching Resource and Action, expect ALLOWED", func(t *testing.T) {
		// Arrange
		ctrl := policyValidator{
			Policies: []Policy{
				{
					Statements: []Statement{
						{
							Resource: "resource1",
							Actions:  []string{"action1", "action2"},
							Effect:   statementEffectAllow,
						},
					},
				},
			},
		}
		ctrl.SetResource("resource1")
		ctrl.SetAction("action2")
		want := ALLOWED

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if result != want {
			t.Errorf("want %v, but got %v", want, result)
		}
		if err != nil {
			t.Errorf("want nil, but got %v", err)
		}
	})

	t.Run("Rule 1 no matched statements (Resource and Action not matched), expect DENIED", func(t *testing.T) {
		// Arrange
		ctrl := policyValidator{
			Policies: []Policy{
				{
					PolicyID: "policy-A",
					Statements: []Statement{
						{
							Effect:     "Allow",
							Resource:   "resource1",
							Actions:    []string{"action1", "action2"},
							Conditions: nil,
						},
					},
				},
				{
					PolicyID: "policy-B",
					Statements: []Statement{
						{
							Effect:     "Allow",
							Resource:   "resource2",
							Actions:    []string{"action1", "action2"},
							Conditions: nil,
						},
					},
				},
			},
		}
		ctrl.SetResource("resource3")
		ctrl.SetAction("action3")

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if err != nil {
			t.Errorf("err: '%v', but want nil", err)
		}
		if result != DENIED {
			t.Errorf("got result '%#v', but want DENIED", result)
		}
	})

	t.Run("Rule 1 no matched statements (AtLeastOne not matched), expect DENIED", func(t *testing.T) {
		// Arrange
		propKey := "key"
		propVal := "value"
		ctrl := policyValidator{
			Policies: []Policy{
				{
					PolicyID: "policy-A",
					Statements: []Statement{
						{
							Effect:   "Allow",
							Resource: "resource1",
							Actions:  []string{"action1", "action2"},
							Conditions: &Condition{
								AtLeastOne: map[string]Comparator{
									propKey: {
										StringEqual: &propVal,
									},
								},
							},
						},
					},
				},
			},
		}
		ctrl.SetResource("resource1")
		ctrl.SetAction("action1")
		ctrl.AddPropertyString(propKey, propVal+"!!!!")

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if err != nil {
			t.Errorf("err: '%v', but want nil", err)
		}
		if result != DENIED {
			t.Errorf("got result '%#v', but want DENIED", result)
		}
	})

	t.Run("Rule 1 no matched statements (MustHaveAll not matched), expect DENIED", func(t *testing.T) {
		// Arrange
		propKey := "key"
		propVal := "value"
		list := []string{"hello", "world"}
		ctrl := policyValidator{
			Policies: []Policy{
				{
					PolicyID: "policy-A",
					Statements: []Statement{
						{
							Effect:   "Allow",
							Resource: "resource1",
							Actions:  []string{"action1", "action2"},
							Conditions: &Condition{
								MustHaveAll: map[string]Comparator{
									propKey: {
										StringEqual: &propVal,
										StringIn:    &list,
									},
								},
							},
						},
					},
				},
			},
		}
		ctrl.SetResource("resource1")
		ctrl.SetAction("action1")
		ctrl.AddPropertyString(propKey, propVal+"!!!!")

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if err != nil {
			t.Errorf("err: '%v', but want nil", err)
		}
		if result != DENIED {
			t.Errorf("got result '%#v', but want DENIED", result)
		}
	})

	t.Run("Rule 2 there is at least one 'Deny', expect DENIED", func(t *testing.T) {
		// Arrange
		propKey := "key"
		propVal := "value"
		ctrl := policyValidator{
			Policies: []Policy{
				{
					PolicyID: "policy-A",
					Statements: []Statement{
						{
							Effect:   "Deny",
							Resource: "resource1",
							Actions:  []string{"action1", "action2"},
							Conditions: &Condition{
								AtLeastOne: map[string]Comparator{
									propKey: {
										StringEqual: &propVal,
									},
								},
							},
						},
						{
							Effect:   "Allow",
							Resource: "resource1",
							Actions:  []string{"action1", "action2"},
							Conditions: &Condition{
								AtLeastOne: map[string]Comparator{
									propKey: {
										StringEqual: &propVal,
									},
								},
							},
						},
					},
				},
			},
		}
		ctrl.SetResource("resource1")
		ctrl.SetAction("action1")
		ctrl.AddPropertyString(propKey, propVal)

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if err != nil {
			t.Errorf("err: '%v', but want nil", err)
		}
		if result != DENIED {
			t.Errorf("got result '%#v', but want DENIED", result)
		}
	})

	t.Run("Rule 3 all matched-statements are 'Allow', expect ALLOWED", func(t *testing.T) {
		// Arrange
		propKey := "key"
		propVal := "value"
		ctrl := policyValidator{
			Policies: []Policy{
				{
					PolicyID: "policy-A",
					Statements: []Statement{
						{
							Effect:   "Allow",
							Resource: "resource1",
							Actions:  []string{"action1", "action2"},
							Conditions: &Condition{
								AtLeastOne: map[string]Comparator{
									propKey: {
										StringEqual: &propVal,
									},
								},
							},
						},
						{
							Effect:   "Allow",
							Resource: "resource1",
							Actions:  []string{"action1", "action2"},
							Conditions: &Condition{
								AtLeastOne: map[string]Comparator{
									propKey: {
										StringEqual: &propVal,
									},
								},
							},
						},
					},
				},
			},
		}
		ctrl.SetResource("resource1")
		ctrl.SetAction("action1")
		ctrl.AddPropertyString(propKey, propVal)

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if err != nil {
			t.Errorf("err: '%v', but want nil", err)
		}
		if result != ALLOWED {
			t.Errorf("got result '%#v', but want ALLOWED", result)
		}
	})

}

func TestSetValidationFunction(t *testing.T) {
	// Arrange
	p := policyValidator{}
	testcases := []struct {
		name string
		b    bool
		err  error
	}{
		{
			name: "fn1",
			b:    true,
			err:  nil,
		},
		{
			name: "fn2",
			b:    false,
			err:  nil,
		},
		{
			name: "fn3",
			b:    false,
			err:  errors.New("error"),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			fn := func(a, b string) (bool, error) {
				return tt.b, tt.err
			}
			p.SetValidationFunction(tt.name, fn)

			// Assert
			gotFn, ok := p.validationFunctions[tt.name]
			if !ok {
				t.Errorf("want true, but got false")
			}
			if r, err := gotFn("", ""); r != tt.b {
				t.Errorf("want %v, but got %v", tt.b, r)
			} else if err != tt.err {
				t.Errorf("want %v, but got %v", tt.err, err)
			}
		})
	}
}

func TestGetValidationFunction(t *testing.T) {
	// Arrange
	p := policyValidator{}
	p.validationFunctions = make(map[string]ValidationFunction)
	testcases := []struct {
		name string
		b    bool
		err  error
	}{
		{
			name: "fn1",
			b:    true,
			err:  nil,
		},
		{
			name: "fn2",
			b:    false,
			err:  nil,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			fn := func(a, b string) (bool, error) {
				return tt.b, tt.err
			}
			p.validationFunctions[tt.name] = fn

			// Act
			gotFn := p.getValidationFunction(tt.name)

			// Assert
			if b, err := gotFn("", ""); b != tt.b {
				t.Errorf("want %v, but got %v", tt.b, b)
			} else if err != tt.err {
				t.Errorf("want %v, but got %v", tt.err, err)
			}
		})
	}
}

func TestGetValidationFunction_NoExpectedFunctionShouldReturnNil(t *testing.T) {
	// Arrange
	p := policyValidator{}
	fn1 := func(a, b string) (bool, error) {
		return true, nil
	}
	p.SetValidationFunction("fn1", fn1)

	// Act
	gotFn1 := p.getValidationFunction("fn1")
	gotFn2 := p.getValidationFunction("fn2")

	// Assert
	if gotFn1 == nil {
		t.Errorf("want not nil, but got nil")
	}
	if gotFn2 != nil {
		t.Errorf("want nil, but got unexpected function")
	}
}

func TestGetSecondArgumentForValidationFunc_PropArg(t *testing.T) {
	// Arrange
	pValidator := New()

	propKey := "prop_key"
	expected := "prop_value"

	prop := Property{
		String: map[string]string{
			propKey: expected,
		},
	}

	comparator := Comparator{
		ValidationFunc: &ValidationFunc{
			PropArg: &propKey,
		},
	}

	// Act
	got, err := pValidator.getSecondArgumentForValidationFunc(prop, comparator)

	// Assert
	if got != expected {
		t.Errorf("got %v, but want %v", got, expected)
	}
	if err != nil {
		t.Errorf("got %v, but want nil", err)
	}

}

func TestGetSecondArgumentForValidationFunc_UserArg(t *testing.T) {
	// Arrange
	userKey := "userKey"
	expected := "John"

	mockUserGetter := &MockUserGetter{
		UserValue: map[string]string{
			userKey: expected,
		},
	}

	pValidator := New()
	pValidator.UserPropertyGetter = mockUserGetter

	prop := Property{}
	comparator := Comparator{
		ValidationFunc: &ValidationFunc{
			UserArg: &userKey,
		},
	}

	// Act
	got, err := pValidator.getSecondArgumentForValidationFunc(prop, comparator)

	// Assert
	if got != expected {
		t.Errorf("got %v, but want %v", got, expected)
	}
	if err != nil {
		t.Errorf("got %v, but want nil", err)
	}
	if !mockUserGetter.WasCalled {
		t.Error("mock function was not called, expect called")
	}
	if mockUserGetter.WhatIsParam != userKey {
		t.Errorf("got %v, but want %v", mockUserGetter.WhatIsParam, userKey)
	}
}

func TestGetSecondArgumentForValidationFunc_StringArg(t *testing.T) {
	// Arrange
	expected := "Expected Value"

	pValidator := New()

	prop := Property{}
	comparator := Comparator{
		ValidationFunc: &ValidationFunc{
			StringArg: &expected,
		},
	}

	// Act
	got, err := pValidator.getSecondArgumentForValidationFunc(prop, comparator)

	// Assert
	if got != expected {
		t.Errorf("got %v, but want %v", got, expected)
	}
	if err != nil {
		t.Errorf("got %v, but want nil", err)
	}
}

func TestGetSecondArgumentForValidationFunc_ErrHaveMoreThan1Args(t *testing.T) {
	// Arrange
	pValidator := New()

	propArg := "prop_arg"
	userArg := "user_arg"

	prop := Property{}
	comparator := Comparator{
		ValidationFunc: &ValidationFunc{
			PropArg: &propArg,
			UserArg: &userArg,
		},
	}

	// Act
	got, err := pValidator.getSecondArgumentForValidationFunc(prop, comparator)

	// Assert
	if got != "" {
		t.Errorf("got %v, but want empty string", got)
	}
	if err == nil {
		t.Error("want error, but got nil")
	}
}

func TestGetSecondArgumentForValidationFunc_ErrHaveNoArgs(t *testing.T) {
	// Arrange
	pValidator := New()

	prop := Property{}
	comparator := Comparator{
		ValidationFunc: &ValidationFunc{}, // no args
	}

	// Act
	got, err := pValidator.getSecondArgumentForValidationFunc(prop, comparator)

	// Assert
	if got != "" {
		t.Errorf("got %v, but want empty string", got)
	}
	if err == nil {
		t.Error("want error, but got nil")
	}
}

func TestIsAccessAllowed_UseValidatorOverrideWithoutAnyData(t *testing.T) {
	// Arrange
	b := []byte{}
	p, err := ParsePolicyArray(b)
	if err != nil {
		t.Error(err)
	}
	ctrl := policyValidator{
		Policies:           p,
		UserPropertyGetter: nil,
		ValidationOverrider: &MockValidationOverrider{
			Result: ALLOWED,
			Error:  nil,
		},
	}

	// Act
	result, err := ctrl.IsAccessAllowed()

	// Assert
	if result != ALLOWED {
		t.Errorf("want ALLOWED, but got %v", result)
	}
	if err != nil {
		t.Errorf("want nil, but got %v", err)
	}

}

func TestIsAccessAllowed_FromParseJSON(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		resource Resource
		expected bool
	}{
		{
			name:     "[full conditions] matched Allow statement, expect ALLOWED",
			file:     "test_data/is_access_allowed/1policy_full_conditions.json",
			expected: ALLOWED,
			resource: Resource{
				Resource: "res:::resource_1",
				Action:   "act:::resource_1:action_1",
				Properties: Property{
					String: map[string]string{
						"prop:::resource_1:prop_1": "hello",
					},
					Integer: map[string]int{
						"prop:::resource_1:prop_3": 1,
					},
					Boolean: map[string]bool{
						"prop:::resource_1:prop_4": true,
					},
				},
			},
		},
		{
			name:     "[full conditions] matched Deny statement, expect DENIED",
			file:     "test_data/is_access_allowed/1policy_full_conditions.json",
			expected: DENIED,
			resource: Resource{
				Resource: "res:::resource_2",
				Action:   "act:::resource_2:action_1",
				Properties: Property{
					String: map[string]string{
						"prop:::resource_2:prop_1": "hello",
					},
					Float: map[string]float64{
						"prop:::resource_2:prop_3": 1.1,
					},
					Boolean: map[string]bool{
						"prop:::resource_2:prop_4": false,
					},
				},
			},
		},
		{
			name:     "[full conditions] no matched statement, expect DENIED",
			file:     "test_data/is_access_allowed/1policy_full_conditions.json",
			expected: DENIED,
			resource: Resource{
				Resource: "res:::resource_3",
				Action:   "act:::resource_3:action_1",
			},
		},
		{
			name:     "[partial conditions] matched Allow statement, expect ALLOWED",
			file:     "test_data/is_access_allowed/1policy_partial_conditions.json",
			expected: ALLOWED,
			resource: Resource{
				Resource: "res:::resource_1",
				Action:   "act:::resource_1:action_1",
				Properties: Property{
					String: map[string]string{
						"prop:::resource_1:prop_1": "hello",
					},
				},
			},
		},
		{
			name:     "[partial conditions] matched Deny statement, expect DENIED",
			file:     "test_data/is_access_allowed/1policy_partial_conditions.json",
			expected: DENIED,
			resource: Resource{
				Resource: "res:::resource_2",
				Action:   "act:::resource_2:action_1",
				Properties: Property{
					Float: map[string]float64{
						"prop:::resource_2:prop_3": 1.1,
					},
					Boolean: map[string]bool{
						"prop:::resource_2:prop_4": false,
					},
				},
			},
		},
		{
			name:     "[no conditions] matched Allow statement, expect ALLOWED",
			file:     "test_data/is_access_allowed/1policy_no_conditions.json",
			expected: ALLOWED,
			resource: Resource{
				Resource: "res:::resource_1",
				Action:   "act:::resource_1:action_1",
			},
		},
		{
			name:     "[no conditions] matched Deny statement, expect DENIED",
			file:     "test_data/is_access_allowed/1policy_no_conditions.json",
			expected: DENIED,
			resource: Resource{
				Resource: "res:::resource_2",
				Action:   "act:::resource_2:action_1",
			},
		},
		{
			name:     "[nil conditions] matched Allow statement, expect ALLOWED",
			file:     "test_data/is_access_allowed/1policy_nil_conditions.json",
			expected: ALLOWED,
			resource: Resource{
				Resource: "res:::resource_1",
				Action:   "act:::resource_1:action_1",
			},
		},
		{
			name:     "[nil conditions] matched Deny statement, expect DENIED",
			file:     "test_data/is_access_allowed/1policy_nil_conditions.json",
			expected: DENIED,
			resource: Resource{
				Resource: "res:::resource_2",
				Action:   "act:::resource_2:action_1",
			},
		},
	}

	for _, test := range tests {
		// Arrange
		b, _ := os.ReadFile(test.file)
		p, _ := ParsePolicyArray(b)
		ctrl := policyValidator{
			Policies: p,
		}
		ctrl.SetResource(test.resource.Resource)
		ctrl.SetAction(test.resource.Action)
		for key, val := range test.resource.Properties.String {
			ctrl.AddPropertyString(key, val)
		}
		for key, val := range test.resource.Properties.Integer {
			ctrl.AddPropertyInteger(key, val)
		}
		for key, val := range test.resource.Properties.Float {
			ctrl.AddPropertyFloat(key, val)
		}
		for key, val := range test.resource.Properties.Boolean {
			ctrl.AddPropertyBoolean(key, val)
		}

		// Act
		result, err := ctrl.IsAccessAllowed()

		// Assert
		if err != nil {
			t.Errorf("err: '%v', but want nil", err)
		}
		if result != test.expected {
			t.Errorf("got %v, but want %v", result, test.expected)
		}
	} // end for
}

func TestIsAccessAllowed_NoSetupValidationController(t *testing.T) {
	// Arrange
	ctrl := policyValidator{}
	var expectedResult = DENIED

	// Act
	result, err := ctrl.IsAccessAllowed()

	// Assert
	if result != expectedResult {
		t.Errorf("got %v, but want %v", result, expectedResult)
	}
	if err != nil {
		t.Errorf("got %v, but want %v", err, nil)
	}
}

func TestIsAccessAllowed_ValidationOverrider(t *testing.T) {
	// Arrange
	var expectedResult = ALLOWED
	mock := MockValidationOverrider{
		Result: expectedResult,
		Error:  nil,
	}
	ctrl := policyValidator{
		ValidationOverrider: &mock,
	}

	// Act
	result, err := ctrl.IsAccessAllowed()

	// Assert
	if result != expectedResult {
		t.Errorf("got %v, but want %v", result, expectedResult)
	}
	if err != nil {
		t.Errorf("got %v, but want %v", err, nil)
	}
	if !mock.WasCalled {
		t.Error("mock function was not called, expect called")
	}
}

func TestIsMatchedComparator_String(t *testing.T) {
	ctrl := policyValidator{}
	valueRefKey := "key"
	testCases := []struct {
		name                string
		want                bool
		propString          string
		expectedStringEqual string
		expectedStringIn    []string
	}{
		{
			name:                "Equal",
			want:                true,
			propString:          "hello",
			expectedStringEqual: "hello",
		},
		{
			name:                "Not Equal",
			want:                false,
			propString:          "hello",
			expectedStringEqual: "bye",
		},
		{
			name:             "In",
			want:             true,
			propString:       "hello",
			expectedStringIn: []string{"hello", "world"},
		},
		{
			name:             "Not In",
			want:             false,
			propString:       "bye",
			expectedStringIn: []string{"hello", "world"},
		},
		{
			name:                "Both Equal and In",
			want:                true,
			propString:          "hello",
			expectedStringEqual: "hello",
			expectedStringIn:    []string{"hello", "world"},
		},
		{
			name:                "Not Equal and not In",
			want:                false,
			propString:          "bye",
			expectedStringEqual: "hello",
			expectedStringIn:    []string{"hello", "world"},
		},
		{
			name:                "Equal, but not In",
			want:                false,
			propString:          "bye",
			expectedStringEqual: "bye",
			expectedStringIn:    []string{"hello", "world"},
		},
		{
			name:                "Not Equal, but In",
			want:                false,
			propString:          "hello",
			expectedStringEqual: "bye",
			expectedStringIn:    []string{"hello", "world"},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			prop := Property{
				String: map[string]string{valueRefKey: tt.propString},
			}
			comparator := Comparator{}
			if tt.expectedStringEqual != "" {
				comparator.StringEqual = &tt.expectedStringEqual
			}
			if len(tt.expectedStringIn) != 0 {
				comparator.StringIn = &tt.expectedStringIn
			}

			// Act
			got := ctrl.isMatchedComparator(comparator, prop, valueRefKey)

			// Assert
			if got != tt.want {
				t.Errorf("got %v, but want %v", got, tt.want)
			}
		})
	}
}

func TestIsMatchedComparator_Integer(t *testing.T) {
	ctrl := policyValidator{}
	valueRefKey := "key"
	testCases := []struct {
		name                 string
		want                 bool
		propInteger          int
		expectedIntegerEqual int
		expectedIntegerIn    []int
	}{
		{
			name:                 "Equal",
			want:                 true,
			propInteger:          1,
			expectedIntegerEqual: 1,
		},
		{
			name:                 "Not Equal",
			want:                 false,
			propInteger:          1,
			expectedIntegerEqual: 2,
		},
		{
			name:              "In",
			want:              true,
			propInteger:       1,
			expectedIntegerIn: []int{1, 2},
		},
		{
			name:              "Not In",
			want:              false,
			propInteger:       3,
			expectedIntegerIn: []int{1, 2},
		},
		{
			name:                 "Both Equal and In",
			want:                 true,
			propInteger:          1,
			expectedIntegerEqual: 1,
			expectedIntegerIn:    []int{1, 2},
		},
		{
			name:                 "Not Equal and Not In",
			want:                 false,
			propInteger:          3,
			expectedIntegerEqual: 1,
			expectedIntegerIn:    []int{1, 2},
		},
		{
			name:                 "Equal, but not In",
			want:                 false,
			propInteger:          3,
			expectedIntegerEqual: 3,
			expectedIntegerIn:    []int{1, 2},
		},
		{
			name:                 "Not Equal, but In",
			want:                 false,
			propInteger:          1,
			expectedIntegerEqual: 3,
			expectedIntegerIn:    []int{1, 2},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			prop := Property{
				Integer: map[string]int{valueRefKey: tt.propInteger},
			}
			comparator := Comparator{}
			if tt.expectedIntegerEqual != 0 {
				comparator.IntegerEqual = &tt.expectedIntegerEqual
			}
			if len(tt.expectedIntegerIn) != 0 {
				comparator.IntegerIn = &tt.expectedIntegerIn
			}

			// Act
			got := ctrl.isMatchedComparator(comparator, prop, valueRefKey)

			// Assert
			if got != tt.want {
				t.Errorf("got %v, but want %v", got, tt.want)
			}
		})
	}
}

func TestIsMatchedComparator_Float(t *testing.T) {
	ctrl := policyValidator{}
	valueRefKey := "key"
	testCases := []struct {
		name               string
		want               bool
		propFloat          float64
		expectedFloatEqual float64
		expectedFloatIn    []float64
	}{
		{
			name:               "Equal",
			want:               true,
			propFloat:          1,
			expectedFloatEqual: 1,
		},
		{
			name:               "Not Equal",
			want:               false,
			propFloat:          1,
			expectedFloatEqual: 2,
		},
		{
			name:            "In",
			want:            true,
			propFloat:       1,
			expectedFloatIn: []float64{1, 2},
		},
		{
			name:            "Not In",
			want:            false,
			propFloat:       3,
			expectedFloatIn: []float64{1, 2},
		},
		{
			name:               "Both Equal and In",
			want:               true,
			propFloat:          1,
			expectedFloatEqual: 1,
			expectedFloatIn:    []float64{1, 2},
		},
		{
			name:               "Not Equal and Not In",
			want:               false,
			propFloat:          3,
			expectedFloatEqual: 1,
			expectedFloatIn:    []float64{1, 2},
		},
		{
			name:               "Equal, but not In",
			want:               false,
			propFloat:          3,
			expectedFloatEqual: 3,
			expectedFloatIn:    []float64{1, 2},
		},
		{
			name:               "Not Equal, but In",
			want:               false,
			propFloat:          1,
			expectedFloatEqual: 3,
			expectedFloatIn:    []float64{1, 2},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			prop := Property{
				Float: map[string]float64{valueRefKey: tt.propFloat},
			}
			comparator := Comparator{}
			if tt.expectedFloatEqual != 0 {
				comparator.FloatEqual = &tt.expectedFloatEqual
			}
			if len(tt.expectedFloatIn) != 0 {
				comparator.FloatIn = &tt.expectedFloatIn
			}

			// Act
			got := ctrl.isMatchedComparator(comparator, prop, valueRefKey)

			// Assert
			if got != tt.want {
				t.Errorf("got %v, but want %v", got, tt.want)
			}
		})
	}
}

func TestIsMatchedComparator_Bool(t *testing.T) {
	ctrl := policyValidator{}
	valueRefKey := "key"
	testCases := []struct {
		name                 string
		want                 bool
		propBoolean          bool
		expectedBooleanEqual bool
	}{
		{
			name:                 "Equal",
			want:                 true,
			propBoolean:          true,
			expectedBooleanEqual: true,
		},
		{
			name:                 "Not Equal",
			want:                 false,
			propBoolean:          true,
			expectedBooleanEqual: false,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			prop := Property{
				Boolean: map[string]bool{valueRefKey: tt.propBoolean},
			}
			comparator := Comparator{
				BooleanEqual: &tt.expectedBooleanEqual,
			}

			// Act
			got := ctrl.isMatchedComparator(comparator, prop, valueRefKey)

			// Assert
			if got != tt.want {
				t.Errorf("got %v, but want %v", got, tt.want)
			}
		})
	}
}

func TestIsMatchedComparator_UserProp(t *testing.T) {
	t.Run("matched", func(t *testing.T) {
		// Arrange
		want := true
		valueRefKey := "prop-key"
		propValue := "value1"
		userKey := "user-key1"
		mock := MockUserGetter{
			UserValue: map[string]string{
				"user-key1": "value1",
				"user-key2": "value2",
			},
		}
		ctrl := policyValidator{
			UserPropertyGetter: &mock,
		}
		comparator := Comparator{
			UserPropEqual: &userKey,
		}
		prop := Property{
			String: map[string]string{valueRefKey: propValue},
		}

		// Act
		got := ctrl.isMatchedComparator(comparator, prop, valueRefKey)

		// Assert
		if got != want {
			t.Errorf("got %v, but want %v", got, want)
		}
		if !mock.WasCalled {
			t.Errorf("mock function was not called, expect called")
		}
		if mock.WhatIsParam != "user-key1" {
			t.Errorf("param is '%v', but expect 'user-key1'", mock.WhatIsParam)
		}
	})

	t.Run("not matched", func(t *testing.T) {
		// Arrange
		want := false
		valueRefKey := "prop-key"
		propValue := "value1"
		userKey := "user-key1"
		mock := MockUserGetter{
			UserValue: map[string]string{
				"user-key1": "value1111",
				"user-key2": "value2222",
			},
		}
		ctrl := policyValidator{
			UserPropertyGetter: &mock,
		}
		comparator := Comparator{
			UserPropEqual: &userKey,
		}
		prop := Property{
			String: map[string]string{valueRefKey: propValue},
		}

		// Act
		got := ctrl.isMatchedComparator(comparator, prop, valueRefKey)

		// Assert
		if got != want {
			t.Errorf("got %v, but want %v", got, want)
		}
		if !mock.WasCalled {
			t.Errorf("mock function was not called, expect called")
		}
		if mock.WhatIsParam != "user-key1" {
			t.Errorf("param is '%v', but expect 'user-key1'", mock.WhatIsParam)
		}
	})

}

func TestExtractStatements(t *testing.T) {
	tests := []struct {
		name     string
		policies []Policy
		want     []Statement
	}{
		{
			name:     "EmptySlice",
			policies: []Policy{},
			want:     []Statement{},
		},
		{
			name: "SinglePolicy",
			policies: []Policy{
				{
					Statements: []Statement{
						{Resource: "statement1"}, {Resource: "statement2"},
					},
				},
			},
			want: []Statement{{Resource: "statement1"}, {Resource: "statement2"}},
		},
		{
			name: "MultiplePolicies",
			policies: []Policy{
				{
					Statements: []Statement{
						{Resource: "statement1"}, {Resource: "statement2"},
					},
				},
				{
					Statements: []Statement{
						{Resource: "statement3"},
					},
				},
			},
			want: []Statement{{Resource: "statement1"}, {Resource: "statement2"}, {Resource: "statement3"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractStatements(tt.policies); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractStatements() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidEffect(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "effect='ALLOW', expect true",
			input: statementEffectAllow,
			want:  true,
		},
		{
			name:  "effect='DENY', expect true",
			input: statementEffectDeny,
			want:  true,
		},
		{
			name:  "effect='Invalid Effect', expect false",
			input: "Invalid Effect",
			want:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualResult := isValidEffect(tc.input)

			if actualResult != tc.want {
				t.Errorf("Expected result for input '%s' is %v, but got %v", tc.input, tc.want, actualResult)
			}
		})
	}
}

func Test_isMatchedComparator_ValidationFunc_NoMatchedFunc_ExpectFalse(t *testing.T) {
	// Arrange
	pValidator := New()
	pValidator.SetValidationFunction("fn1", func(a, b string) (bool, error) {
		return true, nil
	})

	comparator := Comparator{
		ValidationFunc: &ValidationFunc{
			Function: "func:::fn_unknown",
		},
	}

	// Act
	got := pValidator.isMatchedComparator(comparator, Property{}, "")

	// Assert
	if got != false {
		t.Errorf("got %v, but want %v", got, false)
	}
}

func Test_isMatchedComparator_ValidationFunc(t *testing.T) {
	// Arrange
	pValidator := New()

	pValidator.SetValidationFunction("fn_true", func(a, b string) (bool, error) {
		return true, nil
	})
	pValidator.SetValidationFunction("fn_false", func(a, b string) (bool, error) {
		return false, nil
	})
	pValidator.SetValidationFunction("fn_error", func(a, b string) (bool, error) {
		return false, errors.New("error")
	})

	userKey := "user_key"
	mockUserGetter := &MockUserGetter{
		UserValue: map[string]string{
			userKey: "user_value",
		},
	}
	pValidator.UserPropertyGetter = mockUserGetter

	comparisonTargetField := "prop_key"
	prop := Property{
		String: map[string]string{
			comparisonTargetField: "prop_value",
		},
	}

	testCases := []struct {
		name                  string
		want                  bool
		comparator            Comparator
		prop                  Property
		comparisonTargetField string
	}{
		{
			name: "No matched ValidationFunc, expect false",
			want: false,
			comparator: Comparator{
				ValidationFunc: &ValidationFunc{
					Function: "func:::fn_unknown",
				},
			},
		},
		{
			name: "Matched always true ValidationFunc, expect true",
			want: true,
			comparator: Comparator{
				ValidationFunc: &ValidationFunc{
					Function: "fn_true",
					UserArg:  &userKey,
				},
			},
			prop:                  prop,
			comparisonTargetField: comparisonTargetField,
		},
		{
			name: "Matched always false ValidationFunc, expect false",
			want: false,
			comparator: Comparator{
				ValidationFunc: &ValidationFunc{
					Function: "fn_false",
					UserArg:  &userKey,
				},
			},
		},
		{
			name: "Matched always error ValidationFunc, expect false",
			want: false,
			comparator: Comparator{
				ValidationFunc: &ValidationFunc{
					Function: "fn_error",
					UserArg:  &userKey,
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got := pValidator.isMatchedComparator(tt.comparator, tt.prop, tt.comparisonTargetField)

			// Assert
			if got != tt.want {
				t.Errorf("got %v, but want %v", got, tt.want)
			}
		})
	}

}
