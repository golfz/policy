package policy

type Policy struct {
	Version   int         `json:"Version"`
	User      User        `json:"User"`
	Statement []Statement `json:"Statement"`
}

type User struct {
	UserID   string `json:"UserID"`
	UserType string `json:"UserType"`
}

type Statement struct {
	Effect    string    `json:"Effect"`
	Resource  string    `json:"Resource"`
	Action    []string  `json:"Action"`
	Condition Condition `json:"Condition"`
}

type Condition struct {
	AtLeastOne  AvailableCondition `json:"AtLeastOne"`
	MustHaveAll AvailableCondition `json:"MustHaveAll"`
}

type AvailableCondition struct {
	StringCondition
	IntegerCondition
	FloatCondition
	BoolCondition
	TimeCondition
}

type StringCondition struct {
	StringIn    map[string][]string `json:"StringIn"`
	StringEqual map[string]string   `json:"StringEqual"`
}

type IntegerCondition struct {
	IntegerIn    map[string][]int `json:"IntegerIn"`
	IntegerEqual map[string]int   `json:"IntegerEqual"`
}

type FloatCondition struct {
	FloatIn    map[string][]float64 `json:"FloatIn"`
	FloatEqual map[string]float64   `json:"FloatEqual"`
}

type BoolCondition struct {
	BooleanIn    map[string][]bool `json:"BooleanIn"`
	BooleanEqual map[string]bool   `json:"BooleanEqual"`
}

type TimeCondition struct {
	TimeRange     map[string]TimeDuration `json:"TimeRange"`
	DateRange     map[string]TimeDuration `json:"DateRange"`
	DateTimeRange map[string]TimeDuration `json:"DateTimeRange"`
}

type TimeDuration struct {
	From string `json:"From"`
	To   string `json:"To"`
}
