package policy

import "fmt"

const (
	statementEffectAllowString = "Allow"
	statementEffectDenyString  = "Deny"
)

const (
	matchedCondition = true
)

func considerStatement(stmt Statement, res Resource) (bool, error) {
	effect, err := getEffectBool(stmt.Effect)
	if err != nil {
		return DENIED, err
	}

	// RULE :
	// If there are no conditions in this statement,
	// then The result of this statement is according to Effect.
	if stmt.Condition == nil {
		return effect, nil
	}

	isMatched, err := isMatchedCondition(stmt.Condition, res)
	if err != nil {
		return DENIED, err
	}

	return false, nil
}

func getEffectBool(effect string) (bool, error) {
	switch effect {
	case statementEffectAllowString:
		return ALLOWED, nil
	case statementEffectDenyString:
		return DENIED, nil
	default:
		return DENIED, fmt.Errorf("invalid effect: %s", effect)
	}
}

func isMatchedCondition(condition Condition, res Resource) (bool, error) {
	isAtLeastOneConditionMatched, err := considerAtLeastOneCondition(condition.AtLeastOne, res)
	if err != nil {
		return DENIED, err
	}

	isMustHaveAllConditionMatched, err := considerMustHaveAllCondition(condition.MustHaveAll, res)
	if err != nil {
		return DENIED, err
	}

	isMatched := isAtLeastOneConditionMatched && isMustHaveAllConditionMatched
	return isMatched, nil
}

