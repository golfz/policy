package policy

import (
	"os"
	"testing"
)

// ----------------------------------------------
// Policy
// ----------------------------------------------

func TestParsePolicy_Full(t *testing.T) {
	// Arrange
	b, err := os.ReadFile("test_data/parse_policy/policy_full.json")
	if err != nil {
		t.Error(err)
	}

	// Act
	p, err := ParsePolicy(b)

	// Assert
	if err != nil {
		t.Error(err)
	}
	if len(p.Statements) != 2 {
		t.Errorf("Expected 2 statements, but got %d", len(p.Statements))
	}
	if p.Statements[0].Effect != "Allow" {
		t.Errorf("Expected Allow, but got %s", p.Statements[0].Effect)
	}
	if p.Statements[1].Effect != "Deny" {
		t.Errorf("Expected Deny, but got %s", p.Statements[1].Effect)
	}
	if p.Statements[0].Conditions == nil {
		t.Error("Expected conditions in the first statement to be not nil")
	}
	if p.Statements[1].Conditions == nil {
		t.Error("Expected conditions in the second statement to be not nil")
	}
	if p.Statements[1].Conditions.AtLeastOne == nil {
		t.Error("Expected AtLeastOne in the second statement to be not nil")
	}
	if p.Statements[1].Conditions.MustHaveAll == nil {
		t.Error("Expected MustHaveAll in the second statement to be not nil")
	}
	if len(p.Statements[1].Conditions.AtLeastOne) != 2 {
		t.Errorf("Expected 2 AtLeastOne conditions, but got %d", len(p.Statements[1].Conditions.AtLeastOne))
	}
	if len(p.Statements[1].Conditions.MustHaveAll) != 2 {
		t.Errorf("Expected 2 MustHaveAll conditions, but got %d", len(p.Statements[1].Conditions.MustHaveAll))
	}

	if p.Statements[0].Conditions.AtLeastOne["prop:::resource_1:prop_1"].StringEqual == nil {
		t.Error("Expected StringEqual in the first statement to be not nil")
	}
	if *p.Statements[0].Conditions.AtLeastOne["prop:::resource_1:prop_1"].StringEqual != "hello" {
		t.Errorf("Expected hello, but got %s", *p.Statements[0].Conditions.AtLeastOne["prop:::resource_1:prop_1"].StringEqual)
	}
}

func TestParsePolicy_NoCondition(t *testing.T) {
	// Arrange
	b, err := os.ReadFile("test_data/parse_policy/policy_no_condition.json")
	if err != nil {
		t.Error(err)
	}

	// Act
	p, err := ParsePolicy(b)

	// Assert
	if err != nil {
		t.Error(err)
	}
	if len(p.Statements) != 1 {
		t.Errorf("Expected 2 statements, but got %d", len(p.Statements))
	}
	if p.Statements[0].Conditions != nil {
		t.Error("Expected conditions in the first statement to be nil")
	}

}

// ----------------------------------------------
// PolicyArray
// ----------------------------------------------

func TestParsePolicyArray_Full(t *testing.T) {
	// Arrange
	b, err := os.ReadFile("test_data/parse_policy/policy_array_full.json")
	if err != nil {
		t.Error(err)
	}

	// Act
	p, err := ParsePolicyArray(b)

	// Assert
	if err != nil {
		t.Error(err)
	}
	if len(p) != 2 {
		t.Errorf("Expected 2 policies, but got %d", len(p))
	}
	if len(p[0].Statements) != 2 {
		t.Errorf("Expected 2 statements in the first policy, but got %d", len(p[0].Statements))
	}
	if len(p[1].Statements) != 2 {
		t.Errorf("Expected 2 statements in the second policy, but got %d", len(p[1].Statements))
	}
	if p[0].Statements[0].Effect != "Allow" {
		t.Errorf("Expected Allow in the first policy, but got %s", p[0].Statements[0].Effect)
	}
	if p[0].Statements[1].Effect != "Deny" {
		t.Errorf("Expected Deny in the first policy, but got %s", p[0].Statements[1].Effect)
	}
	if p[1].Statements[0].Effect != "Allow" {
		t.Errorf("Expected Allow in the second policy, but got %s", p[1].Statements[0].Effect)
	}
	if p[1].Statements[1].Effect != "Deny" {
		t.Errorf("Expected Deny in the second policy, but got %s", p[1].Statements[1].Effect)
	}
}
