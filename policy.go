package policy

type ResultEffect int

const (
	ignored ResultEffect = 0
	ALLOWED ResultEffect = 1
	DENIED  ResultEffect = 2
)

func (p *Policy) IsAccessAllowed(res Resource) (ResultEffect, error) {
	if p.Error != nil {
		return DENIED, p.Error
	}

	statements := p.getStatementsForResource(res)

	// RULE 1:
	// If there are no matched-statements, then the action is denied.
	if len(statements) == 0 {
		return DENIED, nil
	}

	var countAllow, countDeny uint

	// Consider each statement
	for _, stmt := range statements {
		effect, err := considerStatement(stmt, res)
		if err != nil {
			return DENIED, err
		}

		switch effect {
		case ALLOWED:
			countAllow++
		case DENIED:
			countDeny++
		}
	}

	// RULE 2:
	// If found at least one statement with effect "Deny", then the action is "DENIED".
	if countDeny > 0 {
		return DENIED, nil
	}

	// RULE 3:
	// If not found any statement with effect "Deny",
	// and found at least one statement with effect "Allow",
	// then the action is "ALLOWED".
	if countAllow > 0 {
		return ALLOWED, nil
	}

	// RULE 4:
	// If not found any statement with effect "Deny" and "Allow",
	// then the action is "DENIED".
	return DENIED, nil
}

func (p *Policy) getStatementsForResource(res Resource) []Statement {
	var statements []Statement

	for _, stmt := range p.Statement {
		if stmt.Resource != res.Resource {
			continue
		}
		// If match with resource, then check action
		if isContainsInList(stmt.Action, res.Action) {
			statements = append(statements, stmt)
		}
	}

	return statements
}
