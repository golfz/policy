package policy

import (
	"errors"
	"reflect"
	"testing"
)

func TestIsAccessAllowed(t *testing.T) {
	t.Run("ValidationController with Error, expect error", func(t *testing.T) {
		// Arrange
		ctrl := ValidationController{Err: errors.New("error")}

		// Act
		result, err := ctrl.IsAccessAllowed(Resource{})

		// Assert
		if result != DENIED {
			t.Errorf("want DENIED, but got %v", result)
		}
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("ValidationController with invalid effect, expect error", func(t *testing.T) {
		// Arrange
		ctrl := ValidationController{
			Policies: []Policy{
				{
					Statements: []Statement{
						{Effect: "Invalid Effect"},
					},
				},
			},
		}

		// Act
		result, err := ctrl.IsAccessAllowed(Resource{})

		// Assert
		if result != DENIED {
			t.Errorf("want DENIED, but got %v", result)
		}
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("ValidationController with no matching statements, expect DENIED", func(t *testing.T) {
		// Arrange
		ctrl := ValidationController{
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
		res := Resource{
			Resource: "resource2",
			Action:   "action1",
		}
		want := DENIED

		// Act
		result, err := ctrl.IsAccessAllowed(res)

		// Assert
		if result != want {
			t.Errorf("want %v, but got %v", want, result)
		}
		if err != nil {
			t.Errorf("want nil, but got %v", err)
		}
	})

}

func TestGetMergedStatements(t *testing.T) {
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
			if got := getMergedStatements(tt.policies); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getMergedStatements() = %v, want %v", got, tt.want)
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
			name:  "Allow effect",
			input: statementEffectAllow,
			want:  true,
		},
		{
			name:  "Deny effect",
			input: statementEffectDeny,
			want:  true,
		},
		{
			name:  "Invalid effect",
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
