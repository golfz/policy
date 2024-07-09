package delegate

type Config struct {
	Url  []string `json:"url"`
	From Resource `json:"from"`
	To   Resource `json:"to"`
}

type Resource struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}
