package policy

import (
	"github.com/mastertech-hq/authority/resources"
)

const (
	ALLOWED = true
	DENIED  = false
)

func (p *Policy) IsAccessAllowed(res resources.Resource) (bool, error) {
	statements, err := p.getStatementsForResource(res)
	if err != nil {
		return DENIED, err
	}

	// RULE 1: If there are no statements, then the action is denied.
	if len(statements) == 0 {
		return DENIED, nil
	}

	var countAllow, countDeny uint
	// RULE 2: If found at least one statement with effect "Deny", then the action is "DENIED".
	if countDeny > 0 {
		return DENIED, nil
	}
	// RULE 3: If not found any statement matched with condition, then the action is "DENIED".
	if countDeny == 0 && countAllow == 0 {
		return DENIED, nil
	}

	return ALLOWED, nil
}

func (p *Policy) getStatementsForResource(res resources.Resource) ([]Statement, error) {
	var statements []Statement

	for _, stmt := range p.Statement {
		if stmt.Resource != res.Resource {
			continue
		}
		if isContainsInList(stmt.Action, res.Action) {
			statements = append(statements, stmt)
		}
	}

	return statements, nil
}

func considerStatement(stmt Statement, res resources.Resource) (bool, error) {

	return false, nil
}

func isContainsInList[T comparable](list []T, s T) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func isEquals[T comparable](a, b T) bool {
	return a == b
}
