package userpolicy

// Naming aliases for callers and tests that use the requirement vocabulary.
type (
	UserPolicy        = Policy
	UserRoutingPolicy = Policy
	PolicyConfig      = Config
	UserPolicyTable   = Table
	ZeroTrustPolicy   = Table
)

// NewUserPolicyTable is the descriptive constructor name for NewTable.
func NewUserPolicyTable(config Config) (*Table, error) {
	return NewTable(config)
}

// NewZeroTrustPolicy builds a deny-by-default policy table.
func NewZeroTrustPolicy(policies ...Policy) (*Table, error) {
	return NewTable(Config{Policies: policies, DefaultDeny: true})
}
