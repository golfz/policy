package policy

import "fmt"

func considerPropertyConditions(cons PropertyCondition, res Resource) (int, int, error) {
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
