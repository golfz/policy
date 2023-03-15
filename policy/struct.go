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
	Condition Condition
}

type Condition struct {
	AtLeastOne  AvailableCondition
	MustHaveAll AvailableCondition
}

type AvailableCondition struct {
	StringCondition
	IntegerCondition
	FloatCondition
	BoolCondition
	TimeCondition
}

type StringCondition struct {
	StringIn    map[string][]string
	StringEqual map[string]string
}

type IntegerCondition struct {
	IntegerIn    map[string][]int
	IntegerEqual map[string]int
}

type FloatCondition struct {
	FloatIn    map[string][]float64
	FloatEqual map[string]float64
}

type BoolCondition struct {
	BooleanIn    map[string][]bool
	BooleanEqual map[string]bool
}

type TimeCondition struct {
	TimeRange     map[string]TimeDuration
	DateRange     map[string]TimeDuration
	DateTimeRange map[string]TimeDuration
}

type TimeDuration struct {
	From string `json:"From"`
	To   string `json:"To"`
}
