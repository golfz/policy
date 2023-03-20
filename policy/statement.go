package policy

import (
	"fmt"
)

const (
	statementEffectAllowString = "Allow"
	statementEffectDenyString  = "Deny"
)

const (
	matchedCondition = true
)

func considerStatement(stmt Statement, res Resource) (bool, error) {
	effect, err := convertEffectToboolean(stmt.Effect)
	if err != nil {
		return DENIED, err
	}

	// RULE :
	// If there are no conditions in this statement,
	// then The result of this statement is according to Effect.
	if stmt.Condition == nil {
		return effect, nil
	}

	isMatched, err := considerConditionInStatement(*stmt.Condition, res)
	if err != nil {
		return DENIED, err
	}

	return isMatched, nil
}

func convertEffectToboolean(effect string) (bool, error) {
	switch effect {
	case statementEffectAllowString:
		return ALLOWED, nil
	case statementEffectDenyString:
		return DENIED, nil
	default:
		return DENIED, fmt.Errorf("invalid effect: %s", effect)
	}
}

func considerConditionInStatement(condition Condition, res Resource) (bool, error) {
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

func considerAtLeastOneCondition(cons *AvailableCondition, res Resource) (bool, error) {
	return DENIED, nil
}

func considerMustHaveAllCondition(cons *AvailableCondition, res Resource) (bool, error) {
	return DENIED, nil
}

func considerAvailableConditions(cons AvailableCondition, res Resource) (int, int, error) {
	var matched, total int = 0, 0
	var err error = nil

	// string
	considerIn(cons.StringIn, res.Properties.String, &matched, &total, &err)
	considerEqual(cons.StringEqual, res.Properties.String, &matched, &total, &err)

	return matched, total, nil
}

func considerIn[T comparable](inCons map[string][]T, resProps map[string]T, matched *int, total *int, err *error) {
	if *err != nil {
		return
	}

	if inCons == nil {
		return
	}

	for conProp, conList := range inCons {
		*total++
		resPropValue, ok := resProps[conProp]
		if !ok {
			*err = fmt.Errorf("key %s not found in resource", conProp)
		}
		if isContainsInList(conList, resPropValue) {
			*matched++
		}
	}
}

func considerEqual[T comparable](equalCons map[string]T, resProps map[string]T, matched *int, total *int, err *error) {
	if *err != nil {
		return
	}

	if equalCons == nil {
		return
	}

	for conProp, conValue := range equalCons {
		*total++
		resPropValue, ok := resProps[conProp]
		if !ok {
			*err = fmt.Errorf("key %s not found in resource", conProp)
		}
		if isEquals(conValue, resPropValue) {
			*matched++
		}
	}
}
