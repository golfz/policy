package policy

import "fmt"

const (
	statementEffectAllow = "Allow"
	statementEffectDeny  = "Deny"
)

const (
	conditionMatched    = true
	conditionNotMatched = false
)

type ResultEffect int

const (
	DENIED  ResultEffect = 0
	ALLOWED ResultEffect = 1
)

// ----------------------------------------------
// Policy struct
// ----------------------------------------------

type Policy struct {
	Version    int
	PolicyID   string
	Statements []Statement
}

type Statement struct {
	Effect     string
	Resource   string
	Actions    []string
	Conditions *Condition
}

type Condition struct {
	AtLeastOne  map[string]Comparator
	MustHaveAll map[string]Comparator
}

type Comparator struct {
	StringIn      *[]string
	StringEqual   *string
	IntegerIn     *[]int
	IntegerEqual  *int
	FloatIn       *[]float64
	FloatEqual    *float64
	BooleanEqual  *bool
	UserPropEqual *string
	//TimeRange     map[string]TimeRange
	//DateRange     map[string]TimeRange
	//DateTimeRange map[string]TimeRange
}

//type TimeRange struct {
//	From string
//	To   string
//}

// ----------------------------------------------
// Resource struct
// ----------------------------------------------

type Resource struct {
	Resource   string
	Action     string
	Properties Property
}

type Property struct {
	String  map[string]string
	Integer map[string]int
	Float   map[string]float64
	Boolean map[string]bool
}

// ----------------------------------------------
// interface
// ----------------------------------------------

type UserPropertyGetter interface {
	GetUserProperty(prop string) string
}

type Validator interface {
	IsAccessAllowed(res Resource) (ResultEffect, error)
}

// ----------------------------------------------
// ValidationController
// ----------------------------------------------

type ValidationController struct {
	Policies           []Policy
	UserPropertyGetter UserPropertyGetter
	Err                error
}

// IsAccessAllowed checks if the user is allowed to perform the action on the resource.
func (ctrl *ValidationController) IsAccessAllowed(res Resource) (ResultEffect, error) {
	if ctrl.Err != nil {
		return DENIED, ctrl.Err
	}

	var err error
	statements := getMergedStatements(ctrl.Policies)
	if err = ctrl.validateStatements(statements); err != nil {
		return DENIED, err
	}
	statements, err = ctrl.filterMatchedStatements(statements, res)
	if err != nil {
		return DENIED, err
	}

	// Rule 1: If there are no matching statements, then the result is "DENIED".
	if len(statements) == 0 {
		return DENIED, nil
	}

	// Rule 2: If there is at least one "Deny" statement, then the result is "DENIED".
	for _, stmt := range statements {
		if stmt.Effect == statementEffectDeny {
			return DENIED, nil
		}
	}

	// Rule 3: If all statements are "Allow" statements, then the result is "ALLOWED".
	return ALLOWED, nil
}

// validateStatements function checks if the effect of each statement is valid.
// If the effect is not 'Allow' or 'Deny', it returns an error.
func (ctrl *ValidationController) validateStatements(statements []Statement) error {
	for _, stmt := range statements {
		if !isValidEffect(stmt.Effect) {
			return fmt.Errorf("invalid effect: %s", stmt.Effect)
		}
	}
	return nil
}

func (ctrl *ValidationController) filterMatchedStatements(statements []Statement, res Resource) ([]Statement, error) {
	var filteredStatements []Statement
	for _, stmt := range statements {
		// filter by resource and action
		if stmt.Resource != res.Resource {
			continue
		}
		if !isContainsInList(stmt.Actions, res.Action) {
			continue
		}

		// Rule 4: If there are no conditions, then the statement is considered matched.
		if stmt.Conditions == nil {
			filteredStatements = append(filteredStatements, stmt)
			continue
		}

		isMatched, err := ctrl.considerStatementConditions(*stmt.Conditions, res)
		if err != nil {
			return nil, err
		}
		if isMatched {
			filteredStatements = append(filteredStatements, stmt)
		}
	}
	return filteredStatements, nil
}

func (ctrl *ValidationController) considerStatementConditions(condition Condition, res Resource) (bool, error) {
	isAtLeastOneConditionMatched, err := ctrl.considerAtLeastOneCondition(condition.AtLeastOne, res)
	if err != nil {
		return conditionNotMatched, err
	}

	isMustHaveAllConditionMatched, err := ctrl.considerMustHaveAllCondition(condition.MustHaveAll, res)
	if err != nil {
		return conditionNotMatched, err
	}

	isMatched := isAtLeastOneConditionMatched && isMustHaveAllConditionMatched
	return isMatched, nil
}

func (ctrl *ValidationController) considerAtLeastOneCondition(conditions map[string]Comparator, res Resource) (bool, error) {
	matched, total, err := ctrl.countMatchedConditions(conditions, res)
	if err != nil {
		return conditionNotMatched, err
	}
	if total == 0 {
		return conditionMatched, nil
	}
	return matched > 0, nil
}

func (ctrl *ValidationController) considerMustHaveAllCondition(conditions map[string]Comparator, res Resource) (bool, error) {
	matched, total, err := ctrl.countMatchedConditions(conditions, res)
	if err != nil {
		return conditionNotMatched, err
	}
	if total == 0 {
		return conditionMatched, nil
	}
	return matched == total, nil
}

func (ctrl *ValidationController) countMatchedConditions(conditions map[string]Comparator, res Resource) (matched, total int, err error) {
	total = len(conditions)
	for valueRefKey, comparator := range conditions {
		if ctrl.isMatchedComparator(comparator, res.Properties, valueRefKey) {
			matched++
		}
	}
	return
}

func (ctrl *ValidationController) isMatchedComparator(comparator Comparator, prop Property, valueRefKey string) bool {
	if comparator.StringIn != nil {
		if !isContainsInList(*comparator.StringIn, prop.String[valueRefKey]) {
			return false
		}
	}
	if comparator.StringEqual != nil {
		if *comparator.StringEqual != prop.String[valueRefKey] {
			return false
		}
	}
	if comparator.IntegerIn != nil {
		if !isContainsInList(*comparator.IntegerIn, prop.Integer[valueRefKey]) {
			return false
		}
	}
	if comparator.IntegerEqual != nil {
		if *comparator.IntegerEqual != prop.Integer[valueRefKey] {
			return false
		}
	}
	if comparator.FloatIn != nil {
		if !isContainsInList(*comparator.FloatIn, prop.Float[valueRefKey]) {
			return false
		}
	}
	if comparator.FloatEqual != nil {
		if *comparator.FloatEqual != prop.Float[valueRefKey] {
			return false
		}
	}
	if comparator.BooleanEqual != nil {
		if *comparator.BooleanEqual != prop.Boolean[valueRefKey] {
			return false
		}
	}
	if comparator.UserPropEqual != nil {
		if ctrl.UserPropertyGetter.GetUserProperty(*comparator.UserPropEqual) != prop.String[valueRefKey] {
			return false
		}
	}

	return true
}

// ----------------------------------------------
// Helper functions
// ----------------------------------------------

func getMergedStatements(policies []Policy) []Statement {
	statements := make([]Statement, 0)
	for _, policy := range policies {
		statements = append(statements, policy.Statements...)
	}
	return statements
}

func isValidEffect(effect string) bool {
	return effect == statementEffectAllow || effect == statementEffectDeny
}
