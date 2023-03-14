package policy

import "github.com/mastertech-hq/authority/resources"

func (p *Policy) IsAccessAllowed(r resources.Resource) (bool, error) {
	return true, nil
}
