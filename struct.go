package policy

// ----------------------------------------------
// Policy
// ----------------------------------------------

type ValidationController struct {
	Policies           []Policy
	UserPropertyGetter UserPropertyGetter
	err                error
}

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
