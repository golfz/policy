package policy

type ResultEffect int

const (
	ignored ResultEffect = 0
	ALLOWED ResultEffect = 1
	DENIED  ResultEffect = 2
)

// ----------------------------------------------
// Policy
// ----------------------------------------------

type Policy struct {
	Version    int
	PolicyID   string
	Statements []Statement
	err        error
}

type Statement struct {
	Effect    string
	Resource  string
	Action    []string
	Condition *Condition
}

//type Condition struct {
//	AtLeastOne  *PropertyCondition
//	MustHaveAll *PropertyCondition
//}
//
//type PropertyCondition struct {
//	StringCondition
//	IntegerCondition
//	FloatCondition
//	BooleanCondition
//	TimeCondition
//}

type Condition struct {
	AtLeastOne  map[string]Comparator `json:"AtLeastOne"`
	MustHaveAll map[string]Comparator `json:"MustHaveAll"`
}

type Comparator struct {
	StringIn      *[]string  `json:"StringIn"`
	StringEqual   *string    `json:"StringEqual"`
	IntegerIn     *[]int     `json:"IntegerIn"`
	IntegerEqual  *int       `json:"IntegerEqual"`
	FloatIn       *[]float64 `json:"FloatIn"`
	FloatEqual    *float64   `json:"FloatEqual"`
	BooleanEqual  *bool      `json:"BooleanEqual"`
	UserPropEqual *string    `json:"UserPropEqual"`
	TimeRange     *string    `json:"TimeRange"`
	DateRange     *string    `json:"DateRange"`
	DateTimeRange *string    `json:"DateTimeRange"`
}

type StringCondition struct {
	StringIn    map[string][]string `json:"StringIn,omitempty"`
	StringEqual map[string]string   `json:"StringEqual,omitempty"`
}

type IntegerCondition struct {
	IntegerIn    map[string][]int `json:"IntegerIn,omitempty"`
	IntegerEqual map[string]int   `json:"IntegerEqual,omitempty"`
}

type FloatCondition struct {
	FloatIn    map[string][]float64 `json:"FloatIn,omitempty"`
	FloatEqual map[string]float64   `json:"FloatEqual,omitempty"`
}

type BooleanCondition struct {
	BooleanIn    map[string][]bool `json:"BooleanIn,omitempty"`
	BooleanEqual map[string]bool   `json:"BooleanEqual,omitempty"`
}

type TimeCondition struct {
	TimeRange     map[string]TimeRange `json:"TimeRange,omitempty"`
	DateRange     map[string]TimeRange `json:"DateRange,omitempty"`
	DateTimeRange map[string]TimeRange `json:"DateTimeRange,omitempty"`
}

type TimeRange struct {
	From string
	To   string
}

// ----------------------------------------------
// Resource
// ----------------------------------------------

type Resource struct {
	Resource   string
	Action     string
	Properties Property
}

type Property struct {
	String  map[string]string
	Integer map[string]int
	Float   map[string]float64
	Boolean map[string]bool
}

type UserPropertyGetter interface {
	GetUserProperty(prop string) (interface{}, bool)
}
type Validator interface {
	IsAccessAllowed(res Resource) (ResultEffect, error)
}

type ValidationController struct {
	Policies           []Policy
	UserPropertyGetter UserPropertyGetter
	err                error
}

func (vc *ValidationController) IsAccessAllowed(res Resource) (ResultEffect, error) {
	if vc.err != nil {
		return DENIED, vc.err
	}

	var results []ResultEffect

	for _, p := range vc.Policies {
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
		results = append(results, DENIED)
	}

	// TODO: Implement the logic for combining the results from multiple policies
	return DENIED, nil
}

func (p Policy) getStatementsForResource(res Resource) []Statement {
	var statements []Statement

	for _, stmt := range p.Statements {
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
