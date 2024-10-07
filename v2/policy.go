package policy

import (
	"errors"
	"fmt"
)

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
	StringIn       *[]string
	StringEqual    *string
	IntegerIn      *[]int
	IntegerEqual   *int
	FloatIn        *[]float64
	FloatEqual     *float64
	BooleanEqual   *bool
	UserPropEqual  *string
	ValidationFunc *ValidationFunc
	//TimeRange     map[string]TimeRange
	//DateRange     map[string]TimeRange
	//DateTimeRange map[string]TimeRange
}

type ValidationFunc struct {
	Function  string
	PropArg   *string
	UserArg   *string
	StringArg *string
}

func (v *ValidationFunc) IsValid() bool {
	notNilCount := 0

	if v.PropArg != nil {
		notNilCount++
	}
	if v.UserArg != nil {
		notNilCount++
	}
	if v.StringArg != nil {
		notNilCount++
	}

	return notNilCount == 1
}

//type TimeRange struct {
//	From string
//	To   string
//}

type ValidationFunction func(a, b string) (bool, error)

type policyValidator struct {
	resource            Resource
	Policies            []Policy
	UserPropertyGetter  UserPropertyGetter
	ValidationOverrider ValidationOverrider
	validationFunctions map[string]ValidationFunction
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

func New() *policyValidator {
	return &policyValidator{
		resource: Resource{
			Properties: Property{},
		},
		validationFunctions: make(map[string]ValidationFunction),
	}
}

func (pv *policyValidator) SetValidationFunction(funcName string, fn ValidationFunction) {
	if pv.validationFunctions == nil {
		pv.validationFunctions = make(map[string]ValidationFunction)
	}
	pv.validationFunctions[funcName] = fn
}

func (pv *policyValidator) getValidationFunction(funcName string) ValidationFunction {
	fn, ok := pv.validationFunctions[funcName]
	if !ok {
		return nil
	}
	return fn
}

func (pv *policyValidator) SetResource(resource string) {
	pv.resource.Resource = resource
}

func (pv *policyValidator) SetAction(action string) {
	pv.resource.Action = action
}

func (pv *policyValidator) SetError(err error) {
	pv.Err = err
}

func (pv *policyValidator) AddPropertyString(key string, value string) {
	if pv.resource.Properties.String == nil {
		pv.resource.Properties.String = make(map[string]string)
	}
	pv.resource.Properties.String[key] = value
}

func (pv *policyValidator) AddPropertyInteger(key string, value int) {
	if pv.resource.Properties.Integer == nil {
		pv.resource.Properties.Integer = make(map[string]int)
	}
	pv.resource.Properties.Integer[key] = value
}

func (pv *policyValidator) AddPropertyFloat(key string, value float64) {
	if pv.resource.Properties.Float == nil {
		pv.resource.Properties.Float = make(map[string]float64)
	}
	pv.resource.Properties.Float[key] = value
}

func (pv *policyValidator) AddPropertyBoolean(key string, value bool) {
	if pv.resource.Properties.Boolean == nil {
		pv.resource.Properties.Boolean = make(map[string]bool)
	}
	pv.resource.Properties.Boolean[key] = value
}

// IsAccessAllowed checks if the user is allowed to perform the action on the resource.
func (pv *policyValidator) IsAccessAllowed() (bool, error) {
	if pv.Err != nil {
		return DENIED, pv.Err
	}

	// If there is a validation overrider, use it to determine the result.
	if pv.ValidationOverrider != nil {
		return pv.ValidationOverrider.OverridePolicyValidation(pv.Policies, pv.UserPropertyGetter, pv.resource)
	}

	return pv.validateStatements(extractStatements(pv.Policies))
}

func (pv *policyValidator) validateStatements(statements []Statement) (bool, error) {
	var err error

	if err = pv.checkValidStatements(statements); err != nil {
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

// checkValidStatements function checks if the effect of each statement is valid.
// If the effect is not 'Allow' or 'Deny', it returns an error.
func (pv *policyValidator) checkValidStatements(statements []Statement) error {
	for _, stmt := range statements {
		if !isValidEffect(stmt.Effect) {
			return fmt.Errorf("invalid effect: %s", stmt.Effect)
		}
	}
	return nil
}

func (pv *policyValidator) filterWithResourceAndAction(statements []Statement, res Resource) []Statement {
	var filteredStatements []Statement
	for _, stmt := range statements {
		if stmt.Resource == res.Resource && isContainsInList(stmt.Actions, res.Action) {
			filteredStatements = append(filteredStatements, stmt)
		}
	}
	return filteredStatements
}

func (pv *policyValidator) filterWithStatementConditions(statements []Statement, res Resource) []Statement {
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

func (pv *policyValidator) considerStatementConditions(condition Condition, res Resource) bool {
	isAtLeastOneConditionMatched := pv.considerAtLeastOneCondition(condition.AtLeastOne, res)
	isMustHaveAllConditionMatched := pv.considerMustHaveAllCondition(condition.MustHaveAll, res)
	isMatched := isAtLeastOneConditionMatched && isMustHaveAllConditionMatched
	return isMatched
}

func (pv *policyValidator) considerAtLeastOneCondition(conditions map[string]Comparator, res Resource) bool {
	matched, total := pv.countMatchedConditions(conditions, res)
	if total == 0 {
		return conditionMatched
	}
	if matched > 0 {
		return conditionMatched
	}
	return conditionNotMatched
}

func (pv *policyValidator) considerMustHaveAllCondition(conditions map[string]Comparator, res Resource) bool {
	matched, total := pv.countMatchedConditions(conditions, res)
	if total == 0 {
		return conditionMatched
	}
	if matched == total {
		return conditionMatched
	}
	return conditionNotMatched
}

func (pv *policyValidator) countMatchedConditions(conditions map[string]Comparator, res Resource) (matched, total int) {
	total = len(conditions)
	for valueRefKey, comparator := range conditions {
		if pv.isMatchedComparator(comparator, res.Properties, valueRefKey) {
			matched++
		}
	}
	return matched, total
}

func (pv *policyValidator) isMatchedComparator(comparator Comparator, prop Property, comparisonTargetField string) bool {
	if comparator.StringIn != nil {
		if !isContainsInList(*comparator.StringIn, prop.String[comparisonTargetField]) {
			return false
		}
	}
	if comparator.StringEqual != nil {
		if !isEquals(*comparator.StringEqual, prop.String[comparisonTargetField]) {
			return false
		}
	}
	if comparator.IntegerIn != nil {
		if !isContainsInList(*comparator.IntegerIn, prop.Integer[comparisonTargetField]) {
			return false
		}
	}
	if comparator.IntegerEqual != nil {
		if !isEquals(*comparator.IntegerEqual, prop.Integer[comparisonTargetField]) {
			return false
		}
	}
	if comparator.FloatIn != nil {
		if !isContainsInList(*comparator.FloatIn, prop.Float[comparisonTargetField]) {
			return false
		}
	}
	if comparator.FloatEqual != nil {
		if !isEquals(*comparator.FloatEqual, prop.Float[comparisonTargetField]) {
			return false
		}
	}
	if comparator.BooleanEqual != nil {
		if !isEquals(*comparator.BooleanEqual, prop.Boolean[comparisonTargetField]) {
			return false
		}
	}
	if comparator.UserPropEqual != nil {
		if pv.UserPropertyGetter.GetUserProperty(*comparator.UserPropEqual) != prop.String[comparisonTargetField] {
			return false
		}
	}

	if comparator.ValidationFunc != nil {
		fn := pv.getValidationFunction(comparator.ValidationFunc.Function)
		if fn == nil {
			return false
		}

		firstArg := prop.String[comparisonTargetField]
		secondArg, err := pv.getSecondArgumentForValidationFunc(prop, comparator)
		if err != nil {
			return false
		}

		isMatched, err := fn(firstArg, secondArg)
		if err != nil {
			return false
		}
		return isMatched
	}

	return true
}

func (pv *policyValidator) getSecondArgumentForValidationFunc(prop Property, comparator Comparator) (string, error) {
	if !comparator.ValidationFunc.IsValid() {
		return "", errors.New("invalid second argument for validation function, must not have exactly one argument")

	} else if comparator.ValidationFunc.StringArg != nil {
		return *comparator.ValidationFunc.StringArg, nil

	} else if comparator.ValidationFunc.PropArg != nil {
		return prop.String[*comparator.ValidationFunc.PropArg], nil

	} else if comparator.ValidationFunc.UserArg != nil {
		return pv.UserPropertyGetter.GetUserProperty(*comparator.ValidationFunc.UserArg), nil

	} else {
		return "", errors.New("invalid second argument for validation function, no argument provided")
	}
}

// ----------------------------------------------
// Helper functions
// ----------------------------------------------

// extractStatements will merge all statements from all policies to a single slice.
func extractStatements(policies []Policy) []Statement {
	statements := make([]Statement, 0)
	for _, policy := range policies {
		statements = append(statements, policy.Statements...)
	}
	return statements
}

func isValidEffect(effect string) bool {
	return effect == statementEffectAllow || effect == statementEffectDeny
}
