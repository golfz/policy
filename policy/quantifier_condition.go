package policy

// considerAtLeastOneCondition returns true if at least one condition is matched.
// if there is no condition, return true.
// if there is no matched condition, return false.
func considerAtLeastOneCondition(propertyConditions *PropertyCondition, res Resource) (bool, error) {
	if propertyConditions == nil {
		return conditionMatched, nil
	}

	matched, total, err := considerPropertyConditions(*propertyConditions, res)
	if err != nil {
		return conditionNotMatched, err
	}

	if total == 0 {
		return conditionMatched, nil
	}

	if matched > 0 {
		return conditionMatched, nil
	}

	// total > 0
	// matched == 0
	return conditionNotMatched, nil
}

// considerMustHaveAllCondition returns true if all conditions are matched.
// if there is no condition, return true.
// if at least one condition is not matched, return false.
func considerMustHaveAllCondition(propertyConditions *PropertyCondition, res Resource) (bool, error) {
	if propertyConditions == nil {
		return conditionMatched, nil
	}

	matched, total, err := considerPropertyConditions(*propertyConditions, res)
	if err != nil {
		return conditionNotMatched, err
	}

	if total == 0 {
		return conditionMatched, nil
	}

	if matched == total {
		return conditionMatched, nil
	}

	// total > 0
	// matched < total
	return conditionNotMatched, nil
}
