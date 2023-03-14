package policy

func (p *Policy) IsAccessAllowed() (bool, error) {
	return true, nil
}
