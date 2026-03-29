package status

const (
	ControllerName = "ngxora.dev/control-plane"

	ConditionAccepted       = "Accepted"
	ConditionResolvedRefs   = "ResolvedRefs"
	ConditionProgrammed     = "Programmed"
	ReasonProgrammed        = "Programmed"
	ReasonPending           = "Pending"
	ReasonTranslationFailed = "TranslationFailed"
	ReasonApplyFailed       = "ApplyFailed"
)
