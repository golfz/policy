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
	effect, err := convertEffectToBoolean(stmt.Effect)
	if err != nil {
		return DENIED, err
	}

	// RULE :
	// If there are no conditions in this statement,
	// then The result of this statement is according to Effect.
	if stmt.Condition == nil {
		return effect, nil
	}

	isMatched, err := considerStatementCondition(*stmt.Condition, res)
	if err != nil {
		return DENIED, err
	}

	return isMatched, nil
}

func convertEffectToBoolean(effect string) (bool, error) {
	switch effect {
	case statementEffectAllowString:
		return ALLOWED, nil
	case statementEffectDenyString:
		return DENIED, nil
	default:
		return DENIED, fmt.Errorf("invalid effect: %s", effect)
	}
}

func considerStatementCondition(condition Condition, res Resource) (bool, error) {
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
	if cons == nil {
		return ALLOWED, nil
	}

	matched, total, err := considerAvailableConditions(*cons, res)
	if err != nil {
		return DENIED, err
	}

	if total == 0 {
		return ALLOWED, nil
	}

	if matched > 0 {
		return ALLOWED, nil
	}

	// total > 0 && matched == 0
	return DENIED, nil
}

func considerMustHaveAllCondition(cons *AvailableCondition, res Resource) (bool, error) {
	if cons == nil {
		return ALLOWED, nil
	}

	matched, total, err := considerAvailableConditions(*cons, res)
	if err != nil {
		return DENIED, err
	}

	if total == 0 {
		return ALLOWED, nil
	}

	if matched == total {
		return ALLOWED, nil
	}

	// total > 0 && matched < total
	return DENIED, nil
}

func considerAvailableConditions(cons AvailableCondition, res Resource) (int, int, error) {
	var matched, total int = 0, 0
	var err error = nil

	// string
	considerIn(cons.StringIn, res.Properties.String, &matched, &total, &err)
	considerEqual(cons.StringEqual, res.Properties.String, &matched, &total, &err)

	// int
	considerIn(cons.IntegerIn, res.Properties.Integer, &matched, &total, &err)
	considerEqual(cons.IntegerEqual, res.Properties.Integer, &matched, &total, &err)

	// float
	considerIn(cons.FloatIn, res.Properties.Float, &matched, &total, &err)
	considerEqual(cons.FloatEqual, res.Properties.Float, &matched, &total, &err)

	// bool
	considerIn(cons.BooleanIn, res.Properties.Boolean, &matched, &total, &err)
	considerEqual(cons.BooleanEqual, res.Properties.Boolean, &matched, &total, &err)

	return matched, total, err
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
