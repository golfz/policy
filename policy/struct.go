package policy

type Policy struct {
	Version   int
	PolicyID  string
	Statement []Statement
}

type Statement struct {
	Effect    string
	Resource  string
	Action    []string
	Condition *Condition
}

type Condition struct {
	AtLeastOne  *AvailableCondition
	MustHaveAll *AvailableCondition
}

type AvailableCondition struct {
	StringCondition
	IntegerCondition
	FloatCondition
	BoolCondition
	TimeCondition
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

type BoolCondition struct {
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
