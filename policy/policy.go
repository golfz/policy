package policy

import "github.com/mastertech-hq/authority/resources"

func (p *Policy) IsAccessAllowed(r resources.Resource) (bool, error) {
	return true, nil
}

func (p *Policy) getStatementsForResource(res resources.Resource) ([]Statement, error) {
	var statements []Statement

	for _, stmt := range p.Statement {
		if stmt.Resource != res.Resource {
			continue
		}
		isContains := func(list []string, s string) bool {
			for _, v := range list {
				if v == s {
					return true
				}
			}
			return false
		}
		if isContains(stmt.Action, res.Action) {
			statements = append(statements, stmt)
		}
	}

	return statements, nil
}
