package policy

type Policy struct {
	Version   int
	Statement []Statement
}

type Statement struct {
	Effect    string
	Action    []string
	Resource  []string
	Condition struct {
		StringEqual map[string]string
		StringLike  map[string]string
		StringIn    map[string][]string
		IntEqual    map[string]int
		IntIn       map[string][]int
		FloatEqual  map[string]float64
		FloatIn     map[string][]float64
		BoolEqual   map[string]bool
	} `json:"condition"`
}
