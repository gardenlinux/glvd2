//nolint:tagliatelle // schema not defined by us
package cvss_v3_x

// CVSSV3_x: 3.0 and 3.1 share the same structure, but are scored differently.
type CVSSV3_x struct {
	Version                       string                         `json:"version"`
	VectorString                  string                         `json:"vectorString"`
	BaseScore                     float32                        `json:"baseScore"`
	BaseSeverity                  BaseSeverityType               `json:"baseSeverity"`
	AttackVector                  AttackVectorType               `json:"attackVector,omitempty"`
	AttackComplexity              AttackComplexityType           `json:"attackComplexity,omitempty"`
	PrivilegesRequired            PrivilegesRequiredType         `json:"privilegesRequired,omitempty"`
	UserInteraction               UserInteractionType            `json:"userInteraction,omitempty"`
	Scope                         ScopeType                      `json:"scope,omitempty"`
	ConfidentialityImpact         ImpactType                     `json:"confidentialityImpact,omitempty"`
	IntegrityImpact               ImpactType                     `json:"integrityImpact,omitempty"`
	AvailabilityyImpact           ImpactType                     `json:"availabilityyImpact,omitempty"`
	ExploitCodeMaturity           ExploitCodeMaturityType        `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel              RemediationLevelType           `json:"redemdiationLevel,omitempty"`
	ReportConfidence              ConfidenceType                 `json:"reportConfidence,omitempty"`
	TemporalScore                 float32                        `json:"temporalScore,omitempty"`
	TemporalSeverity              BaseSeverityType               `json:"temporalSeverity,omitempty"`
	ConfidentialityRequirement    CIARequirementType             `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          CIARequirementType             `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       CIARequirementType             `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          ModifiedAttackVectorType       `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      ModifiedAttackComplexityType   `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    ModifiedPrivilegesRequiredType `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       ModifiedUserInteractionType    `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 ModifiedScopeType              `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact ModifiedImpactType             `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       ModifiedImpactType             `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    ModifiedImpactType             `json:"modifiedAvailabilityImpact,omitempty"`
	EnvironmentalScore            float32                        `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         BaseSeverityType               `json:"environmentalSeverity,omitempty"`
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
	AttackVectorTypeADJACENTNETWORK AttackVectorType = "ADJACENT_NETWORK"
	AttackVectorTypeLOCAL           AttackVectorType = "LOCAL"
	AttackVectorTypeNETWORK         AttackVectorType = "NETWORK"
	AttackVectorTypePHYSICAL        AttackVectorType = "PHYSICAL"
)

type AttackComplexityType string

const (
	AttackComplexityTypeLOW  AttackComplexityType = "LOW"
	AttackComplexityTypeHIGH AttackComplexityType = "HIGH"
)

type PrivilegesRequiredType string

const (
	PrivilegesRequiredTypeNONE PrivilegesRequiredType = "NONE"
	PrivilegesRequiredTypeLOW  PrivilegesRequiredType = "LOW"
	PrivilegesRequiredTypeHIGH PrivilegesRequiredType = "HIGH"
)

type UserInteractionType string

const (
	UserInteractionTypeNONE     UserInteractionType = "NONE"
	UserInteractionTypeREQUIRED UserInteractionType = "REQUIRED"
)

type ScopeType string

const (
	ScopeTypeCHANGED   ScopeType = "CHANGED"
	ScopeTypeUNCHANGED ScopeType = "UNCHANGED"
)

type ImpactType string

const (
	ImpactTypeNone ImpactType = "NONE"
	ImpactTypeLow  ImpactType = "LOW"
	ImpactTypeHigh ImpactType = "HIGH"
)

type ExploitCodeMaturityType string

const (
	ExploitCodeMaturityTypeNOTDEFINED     ExploitCodeMaturityType = "NOT_DEFINED"
	ExploitCodeMaturityTypeUNPROVEN       ExploitCodeMaturityType = "UNPROVEN"
	ExploitCodeMaturityTypePROOFOFCONCEPT ExploitCodeMaturityType = "PROOF_OF_CONCEPT"
	ExploitCodeMaturityTypeFUNCTIONAL     ExploitCodeMaturityType = "FUNCTIONAL"
	ExploitCodeMaturityTypeHIGH           ExploitCodeMaturityType = "HIGH"
)

type RemediationLevelType string

const (
	RemediationLevelTypeNOTDEFINED   RemediationLevelType = "NOT_DEFINED"
	RemediationLevelTypeUNAVAILABLE  RemediationLevelType = "UNAVAILABLE"
	RemediationLevelTypeWORKAROUND   RemediationLevelType = "WORKAROUND"
	RemediationLevelTypeTEMPORARYFIX RemediationLevelType = "TEMPORARY_FIX"
	RemediationLevelTypeOFFICIALFIX  RemediationLevelType = "OFFICIAL_FIX"
)

type ConfidenceType string

const (
	ConfidenceTypeUNKNOWN    ConfidenceType = "UNKNOWN"
	ConfidenceTypeNOTDEFINED ConfidenceType = "NOT_DEFINED"
	ConfidenceTypeREASONABLE ConfidenceType = "REASONABLE"
	ConfidenceTypeCONFIRMED  ConfidenceType = "CONFIRMED"
)

type CIARequirementType string

const (
	CIARequirementTypeNOTDEFINED CIARequirementType = "NOT_DEFINED"
	CIARequirementTypeLOW        CIARequirementType = "LOW"
	CIARequirementTypeMEDIUM     CIARequirementType = "MEDIUM"
	CIARequirementTypeHIGH       CIARequirementType = "HIGH"
)

type ModifiedAttackVectorType string

const (
	ModifiedAttackVectorTypeNOTDEFINED      ModifiedAttackVectorType = "NOT_DEFINED"
	ModifiedAttackVectorTypeLOCAL           ModifiedAttackVectorType = "LOCAL"
	ModifiedAttackVectorTypeADJACENTNETWORK ModifiedAttackVectorType = "ADJACENT_NETWORK"
	ModifiedAttackVectorTypeNETWORK         ModifiedAttackVectorType = "NETWORK"
	ModifiedAttackVectorTypePHYSICAL        ModifiedAttackVectorType = "PHYSICAL"
)

type ModifiedAttackComplexityType string

const (
	ModifiedAttackComplexityTypeLOW        ModifiedAttackComplexityType = "LOW"
	ModifiedAttackComplexityTypeNOTDEFINED ModifiedAttackComplexityType = "NOT_DEFINED"
	ModifiedAttackComplexityTypeHIGH       ModifiedAttackComplexityType = "HIGH"
)

type ModifiedPrivilegesRequiredType string

const (
	ModifiedPrivilegesRequiredTypeNOTDEFINED ModifiedPrivilegesRequiredType = "NOT_DEFINED"
	ModifiedPrivilegesRequiredTypeNONE       ModifiedPrivilegesRequiredType = "NONE"
	ModifiedPrivilegesRequiredTypeLOW        ModifiedPrivilegesRequiredType = "LOW"
	ModifiedPrivilegesRequiredTypeHIGH       ModifiedPrivilegesRequiredType = "HIGH"
)

type ModifiedUserInteractionType string

const (
	ModifiedUserInteractionTypeNONE       ModifiedUserInteractionType = "NONE"
	ModifiedUserInteractionTypeNOTDEFINED ModifiedUserInteractionType = "NOT_DEFINED"
	ModifiedUserInteractionTypeREQUIRED   ModifiedUserInteractionType = "REQUIRED"
)

type ModifiedScopeType string

const (
	ModifiedScopeTypeNOTDEFINED ModifiedScopeType = "NOT_DEFINED"
	ModifiedScopeTypeUNCHANGED  ModifiedScopeType = "UNCHANGED"
	ModifiedScopeTypeCHANGED    ModifiedScopeType = "CHANGED"
)

type ModifiedImpactType string

const (
	CIATypeNone       ModifiedImpactType = "NONE"
	CIATypeLow        ModifiedImpactType = "LOW"
	CIATypeHigh       ModifiedImpactType = "HIGH"
	CIATypeNotDefined ModifiedImpactType = "NOT_DEFINED"
)
