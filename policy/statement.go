package policy

import (
	"fmt"
)

const (
	statementEffectAllowString = "Allow"
	statementEffectDenyString  = "Deny"
)

const (
	conditionMatched    = true
	conditionNotMatched = false
)

func considerStatement(stmt Statement, res Resource) (ResultEffect, error) {
	effect, err := convertStringToResultEffect(stmt.Effect)
	if err != nil {
		return ignored, err
	}

	// RULE :
	// If there are no conditions in this statement,
	// then The result of this statement is according to Effect.
	if stmt.Condition == nil {
		return effect, nil
	}

	isMatched, err := considerStatementConditions(*stmt.Condition, res)
	if err != nil {
		return ignored, err
	}

	if isMatched {
		return effect, nil
	}

	return ignored, nil
}

func considerStatementConditions(condition Condition, res Resource) (bool, error) {
	isAtLeastOneConditionMatched, err := considerAtLeastOneCondition(condition.AtLeastOne, res)
	if err != nil {
		return conditionNotMatched, err
	}

	isMustHaveAllConditionMatched, err := considerMustHaveAllCondition(condition.MustHaveAll, res)
	if err != nil {
		return conditionNotMatched, err
	}

	isMatched := isAtLeastOneConditionMatched && isMustHaveAllConditionMatched
	return isMatched, nil
}

func convertStringToResultEffect(effect string) (ResultEffect, error) {
	switch effect {
	case statementEffectAllowString:
		return ALLOWED, nil
	case statementEffectDenyString:
		return DENIED, nil
	default:
		return DENIED, fmt.Errorf("invalid effect: %s", effect)
	}
}
