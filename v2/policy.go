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

const (
	DENIED  = false
	ALLOWED = true
)

type UserPropertyGetter interface {
	GetUserProperty(key string) string
}

type ValidationOverrider interface {
	OverridePolicyValidation(policies []Policy, UserPropertyGetter UserPropertyGetter, res Resource) (bool, error)
}

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

type PolicyValidator struct {
	resource            Resource
	Policies            []Policy
	UserPropertyGetter  UserPropertyGetter
	ValidationOverrider ValidationOverrider
	Err                 error
}

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

func New() *PolicyValidator {
	return &PolicyValidator{
		resource: Resource{
			Properties: Property{},
		},
	}
}

func (pv *PolicyValidator) SetResource(resource string) {
	pv.resource.Resource = resource
}

func (pv *PolicyValidator) SetAction(action string) {
	pv.resource.Action = action
}

func (pv *PolicyValidator) SetError(err error) {
	pv.Err = err
}

func (pv *PolicyValidator) AddPropertyString(key string, value string) {
	if pv.resource.Properties.String == nil {
		pv.resource.Properties.String = make(map[string]string)
	}
	pv.resource.Properties.String[key] = value
}

func (pv *PolicyValidator) AddPropertyInteger(key string, value int) {
	if pv.resource.Properties.Integer == nil {
		pv.resource.Properties.Integer = make(map[string]int)
	}
	pv.resource.Properties.Integer[key] = value
}

func (pv *PolicyValidator) AddPropertyFloat(key string, value float64) {
	if pv.resource.Properties.Float == nil {
		pv.resource.Properties.Float = make(map[string]float64)
	}
	pv.resource.Properties.Float[key] = value
}

func (pv *PolicyValidator) AddPropertyBoolean(key string, value bool) {
	if pv.resource.Properties.Boolean == nil {
		pv.resource.Properties.Boolean = make(map[string]bool)
	}
	pv.resource.Properties.Boolean[key] = value
}

// IsAccessAllowed checks if the user is allowed to perform the action on the resource.
func (pv *PolicyValidator) IsAccessAllowed() (bool, error) {
	if pv.Err != nil {
		return DENIED, pv.Err
	}

	// If there is a validation overrider, use it to determine the result.
	if pv.ValidationOverrider != nil {
		return pv.ValidationOverrider.OverridePolicyValidation(pv.Policies, pv.UserPropertyGetter, pv.resource)
	}

	var err error
	statements := getMergedStatements(pv.Policies)
	if err = pv.validateStatements(statements); err != nil {
		return DENIED, err
	}
	statements = pv.filterWithResourceAndAction(statements, pv.resource)
	statements = pv.filterWithStatementConditions(statements, pv.resource)

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
func (pv *PolicyValidator) validateStatements(statements []Statement) error {
	for _, stmt := range statements {
		if !isValidEffect(stmt.Effect) {
			return fmt.Errorf("invalid effect: %s", stmt.Effect)
		}
	}
	return nil
}

func (pv *PolicyValidator) filterWithResourceAndAction(statements []Statement, res Resource) []Statement {
	var filteredStatements []Statement
	for _, stmt := range statements {
		if stmt.Resource == res.Resource && isContainsInList(stmt.Actions, res.Action) {
			filteredStatements = append(filteredStatements, stmt)
		}
	}
	return filteredStatements
}

func (pv *PolicyValidator) filterWithStatementConditions(statements []Statement, res Resource) []Statement {
	var filteredStatements []Statement
	for _, stmt := range statements {
		// Rule 4: If there are no conditions, then the statement is considered matched.
		if stmt.Conditions == nil {
			filteredStatements = append(filteredStatements, stmt)
			continue
		}

		isMatched := pv.considerStatementConditions(*stmt.Conditions, res)
		if isMatched {
			filteredStatements = append(filteredStatements, stmt)
		}
	}
	return filteredStatements
}

func (pv *PolicyValidator) considerStatementConditions(condition Condition, res Resource) bool {
	isAtLeastOneConditionMatched := pv.considerAtLeastOneCondition(condition.AtLeastOne, res)
	isMustHaveAllConditionMatched := pv.considerMustHaveAllCondition(condition.MustHaveAll, res)
	isMatched := isAtLeastOneConditionMatched && isMustHaveAllConditionMatched
	return isMatched
}

func (pv *PolicyValidator) considerAtLeastOneCondition(conditions map[string]Comparator, res Resource) bool {
	matched, total := pv.countMatchedConditions(conditions, res)
	if total == 0 {
		return conditionMatched
	}
	if matched > 0 {
		return conditionMatched
	}
	return conditionNotMatched
}

func (pv *PolicyValidator) considerMustHaveAllCondition(conditions map[string]Comparator, res Resource) bool {
	matched, total := pv.countMatchedConditions(conditions, res)
	if total == 0 {
		return conditionMatched
	}
	if matched == total {
		return conditionMatched
	}
	return conditionNotMatched
}

func (pv *PolicyValidator) countMatchedConditions(conditions map[string]Comparator, res Resource) (matched, total int) {
	total = len(conditions)
	for valueRefKey, comparator := range conditions {
		if pv.isMatchedComparator(comparator, res.Properties, valueRefKey) {
			matched++
		}
	}
	return
}

func (pv *PolicyValidator) isMatchedComparator(comparator Comparator, prop Property, valueRefKey string) bool {
	if comparator.StringIn != nil {
		if !isContainsInList(*comparator.StringIn, prop.String[valueRefKey]) {
			return false
		}
	}
	if comparator.StringEqual != nil {
		if !isEquals(*comparator.StringEqual, prop.String[valueRefKey]) {
			return false
		}
	}
	if comparator.IntegerIn != nil {
		if !isContainsInList(*comparator.IntegerIn, prop.Integer[valueRefKey]) {
			return false
		}
	}
	if comparator.IntegerEqual != nil {
		if !isEquals(*comparator.IntegerEqual, prop.Integer[valueRefKey]) {
			return false
		}
	}
	if comparator.FloatIn != nil {
		if !isContainsInList(*comparator.FloatIn, prop.Float[valueRefKey]) {
			return false
		}
	}
	if comparator.FloatEqual != nil {
		if !isEquals(*comparator.FloatEqual, prop.Float[valueRefKey]) {
			return false
		}
	}
	if comparator.BooleanEqual != nil {
		if !isEquals(*comparator.BooleanEqual, prop.Boolean[valueRefKey]) {
			return false
		}
	}
	if comparator.UserPropEqual != nil {
		if pv.UserPropertyGetter.GetUserProperty(*comparator.UserPropEqual) != prop.String[valueRefKey] {
			return false
		}
	}

	return true
}

// ----------------------------------------------
// Helper functions
// ----------------------------------------------

// getMergedStatements will merge all statements from all policies to a single slice.
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
