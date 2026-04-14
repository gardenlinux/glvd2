package cvss_v4_0

type CVSSV4_0 struct {
	Version                           string                          `json:"version"`
	VectorString                      string                          `json:"vectorString"`
	BaseScore                         float32                         `json:"baseScore"`
	BaseSeverity                      BaseSeverityType                `json:"baseSeverity"`
	AttackVector                      AttackVectorType                `json:"attackVector,omitempty"`
	AttackComplexity                  AttackComplexityType            `json:"attackComplexity,omitempty"`
	AttackRequirements                AttackRequirementsType          `json:"attackRequirements,omitempty"`
	PrivilegesRequired                PrivilegesRequiredType          `json:"privilegesRequired,omitempty"`
	UserInteraction                   UserInteractionType             `json:"userInteraction,omitempty"`
	VulnConfidentialityImpact         ImpactType                      `json:"vulnConfidentialityImpact,omitempty"`
	VulnIntegrityImpact               ImpactType                      `json:"vulnIntegrityImpact,omitempty"`
	VulnAvailabilityyImpact           ImpactType                      `json:"vulnAvailabilityyImpact,omitempty"`
	SubConfidentialityImpact          ImpactType                      `json:"subConfidentialityImpact,omitempty"`
	SubIntegrityImpact                ImpactType                      `json:"subIntegrityImpact,omitempty"`
	SubAvailabilityImpact             ImpactType                      `json:"subAvailabilityImpact,omitempty"`
	ExploitMaturity                   ExploitMaturityType             `json:"exploitMaturity,omitempty"`
	ConfidentialityRequirement        CIARequirementType              `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement              CIARequirementType              `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement           CIARequirementType              `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector              ModifiedAttackVectorType        `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity          ModifiedAttackComplexityType    `json:"modifiedAttackComplexity,omitempty"`
	ModifiedAttackRequirements        ModifiedAttackRequirementsType  `json:"modifiedAttackRequirements,omitempty"`
	ModifiedPrivilegesRequired        ModifiedPrivilegesRequiredType  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction           ModifiedUserInteractionType     `json:"modifiedUserInteraction,omitempty"`
	ModifiedVulnConfidentialityImpact ModifiedSubImpactType           `json:"modifiedVulnConfidentialityImpact,omitempty"`
	ModifiedVulnIntegrityImpact       ModifiedSubImpactType           `json:"modifiedVulnIntegrityImpact,omitempty"`
	ModifiedVulnAvailabilityImpact    ModifiedSubImpactType           `json:"modifiedVulnAvailabilityImpact,omitempty"`
	ModifiedSubConfidentialityImpact  ModifiedSubImpactType           `json:"modifiedSubConfidentialityImpact,omitempty"`
	ModifiedSubIntegrityImpact        ModifiedSubIAType               `json:"modifiedSubIntegrityImpact,omitempty"`
	ModifiedSubAvailabilityImpact     ModifiedSubIAType               `json:"modifiedSubAvailabilityImpact,omitempty"`
	Safety                            SafetyType                      `json:"safety,omitempty"`
	Automatable                       AutomatableType                 `json:"automatable,omitempty"`
	Recovery                          RecoveryType                    `json:"recovery,omitempty"`
	ValueDensity                      ValueDensityType                `json:"valueDensity,omitempty"`
	VulnerabilityResponseEffort       VulnerabilityResponseEffortType `json:"vulnerabilityResponseEffort,omitempty"`
	ProviderUrgency                   ProviderUrgencyType             `json:"providerUrgency,omitempty"`
}

type BaseSeverityType string

const (
	SeverityNone     BaseSeverityType = "NONE"
	SeverityLow      BaseSeverityType = "LOW"
	SeverityMedium   BaseSeverityType = "MEDIUM"
	SeverityHigh     BaseSeverityType = "HIGH"
	SeverityCritical BaseSeverityType = "CRITICAL"
)

type AttackVectorType string

const (
	AttackVectorTypeAdjacent AttackVectorType = "ADJACENT"
	AttackVectorTypeLocal    AttackVectorType = "LOCAL"
	AttackVectorTypeNetwork  AttackVectorType = "NETWORK"
	AttackVectorTypePhysical AttackVectorType = "PHYSICAL"
)

type AttackComplexityType string

const (
	AttackComplexityTypeHigh AttackComplexityType = "HIGH"
	AttackComplexityTypeLow  AttackComplexityType = "LOW"
)

type AttackRequirementsType string

const (
	AttackRequirementsTypeNone    AttackRequirementsType = "NONE"
	AttackRequirementsTypePresent AttackRequirementsType = "PRESENT"
)

type PrivilegesRequiredType string

const (
	PrivilegesRequiredTypeHigh PrivilegesRequiredType = "HIGH"
	PrivilegesRequiredTypeLow  PrivilegesRequiredType = "LOW"
	PrivilegesRequiredTypeNone PrivilegesRequiredType = "NONE"
)

type UserInteractionType string

const (
	UserInteractionTypeActive  UserInteractionType = "ACTIVE"
	UserInteractionTypeNone    UserInteractionType = "NONE"
	UserInteractionTypePassive UserInteractionType = "PASSIVE"
)

type ImpactType string

const (
	ImpactTypeNone ImpactType = "NONE"
	ImpactTypeLow  ImpactType = "LOW"
	ImpactTypeHigh ImpactType = "HIGH"
)

type ExploitMaturityType string

const (
	ExploitMaturityTypeAttacked       ExploitMaturityType = "ATTACKED"
	ExploitMaturityTypeNotDefined     ExploitMaturityType = "NOT_DEFINED"
	ExploitMaturityTypeProofOfConcept ExploitMaturityType = "PROOF_OF_CONCEPT"
	ExploitMaturityTypeUnreported     ExploitMaturityType = "UNREPORTED"
)

type CIARequirementType string

const (
	CiaRequirementTypeLow        CIARequirementType = "LOW"
	CiaRequirementTypeMedium     CIARequirementType = "MEDIUM"
	CiaRequirementTypeHigh       CIARequirementType = "HIGH"
	CiaRequirementTypeNotDefined CIARequirementType = "NOT_DEFINED"
)

type ModifiedAttackVectorType string

const (
	ModifiedAttackVectorTypePhysical   ModifiedAttackVectorType = "PHYSICAL"
	ModifiedAttackVectorTypeNetwork    ModifiedAttackVectorType = "NETWORK"
	ModifiedAttackVectorTypeLocal      ModifiedAttackVectorType = "LOCAL"
	ModifiedAttackVectorTypeAdjacent   ModifiedAttackVectorType = "ADJACENT"
	ModifiedAttackVectorTypeNotDefined ModifiedAttackVectorType = "NOT_DEFINED"
)

type ModifiedAttackComplexityType string

const (
	ModifiedAttackComplexityTypeHigh       ModifiedAttackComplexityType = "HIGH"
	ModifiedAttackComplexityTypeLow        ModifiedAttackComplexityType = "LOW"
	ModifiedAttackComplexityTypeNotDefined ModifiedAttackComplexityType = "NOT_DEFINED"
)

type ModifiedAttackRequirementsType string

const (
	ModifiedAttackRequirementsTypeNone       ModifiedAttackRequirementsType = "NONE"
	ModifiedAttackRequirementsTypePresent    ModifiedAttackRequirementsType = "PRESENT"
	ModifiedAttackRequirementsTypeNotDefined ModifiedAttackRequirementsType = "NOT_DEFINED"
)

type ModifiedPrivilegesRequiredType string

const (
	ModifiedPrivilegesRequiredTypeNone       ModifiedPrivilegesRequiredType = "NONE"
	ModifiedPrivilegesRequiredTypeLow        ModifiedPrivilegesRequiredType = "LOW"
	ModifiedPrivilegesRequiredTypeHigh       ModifiedPrivilegesRequiredType = "HIGH"
	ModifiedPrivilegesRequiredTypeNotDefined ModifiedPrivilegesRequiredType = "NOT_DEFINED"
)

type ModifiedUserInteractionType string

const (
	ModifiedUserInteractionTypeNone       ModifiedUserInteractionType = "NONE"
	ModifiedUserInteractionTypeActive     ModifiedUserInteractionType = "ACTIVE"
	ModifiedUserInteractionTypePassive    ModifiedUserInteractionType = "PASSIVE"
	ModifiedUserInteractionTypeNotDefined ModifiedUserInteractionType = "NOT_DEFINED"
)

type ModifiedSubIAType string

const (
	ModifiedSubIaTypeNone       ModifiedSubIAType = "NONE"
	ModifiedSubIaTypeLow        ModifiedSubIAType = "LOW"
	ModifiedSubIaTypeHigh       ModifiedSubIAType = "HIGH"
	ModifiedSubIaTypeSafety     ModifiedSubIAType = "SAFETY"
	ModifiedSubIaTypeNotDefined ModifiedSubIAType = "NOT_DEFINED"
)

type ModifiedSubImpactType string

const (
	SubCIATypeNone       ModifiedSubImpactType = "NONE"
	SubCIATypeLow        ModifiedSubImpactType = "LOW"
	SubCIATypeHigh       ModifiedSubImpactType = "HIGH"
	SubCIATypeNotDefined ModifiedSubImpactType = "NOT_DEFINED"
)

type SafetyType string

const (
	SafetyTypeNegligible SafetyType = "NEGLIGIBLE"
	SafetyTypePresent    SafetyType = "PRESENT"
	SafetyTypeNotDefined SafetyType = "NOT_DEFINED"
)

type AutomatableType string

const (
	AutomatableTypeYes        AutomatableType = "YES"
	AutomatableTypeNo         AutomatableType = "NO"
	AutomatableTypeNotDefined AutomatableType = "NOT_DEFINED"
)

type RecoveryType string

const (
	RecoveryTypeUser          RecoveryType = "USER"
	RecoveryTypeAutomatic     RecoveryType = "AUTOMATIC"
	RecoveryTypeIrrecoverable RecoveryType = "IRRECOVERABLE"
	RecoveryTypeNotDefined    RecoveryType = "NOT_DEFINED"
)

type ValueDensityType string

const (
	ValueDensityTypeDiffuse      ValueDensityType = "DIFFUSE"
	ValueDensityTypeConcentrated ValueDensityType = "CONCENTRATED"
	ValueDensityTypeNotDefined   ValueDensityType = "NOT_DEFINED"
)

type VulnerabilityResponseEffortType string

const (
	VulnerabilityResponseEffortTypeLow        VulnerabilityResponseEffortType = "LOW"
	VulnerabilityResponseEffortTypeModerate   VulnerabilityResponseEffortType = "MODERATE"
	VulnerabilityResponseEffortTypeHigh       VulnerabilityResponseEffortType = "HIGH"
	VulnerabilityResponseEffortTypeNotDefined VulnerabilityResponseEffortType = "NOT_DEFINED"
)

type ProviderUrgencyType string

const (
	ProviderUrgencyTypeClear      ProviderUrgencyType = "CLEAR"
	ProviderUrgencyTypeGreen      ProviderUrgencyType = "GREEN"
	ProviderUrgencyTypeAmber      ProviderUrgencyType = "AMBER"
	ProviderUrgencyTypeRed        ProviderUrgencyType = "RED"
	ProviderUrgencyTypeNotDefined ProviderUrgencyType = "NOT_DEFINED"
)
