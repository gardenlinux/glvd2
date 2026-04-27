//nolint:tagliatelle // schema not defined by us
package cvss_v2_0

type CVSSV2_0 struct {
	Version                    string                        `json:"version"`
	VectorString               string                        `json:"vectorString"`
	BaseScore                  float32                       `json:"baseScore"`
	AcessVector                AccessVectorType              `json:"accessVector,omitempty"`
	AccessComplexity           AccessComplexityType          `json:"accessComplexity,omitempty"`
	Authentication             AuthenticationType            `json:"authentication,omitempty"`
	ConfidentialityImpact      ImpactType                    `json:"confidentialityImpact,omitempty"`
	IntegrityImpact            ImpactType                    `json:"integrityImpact,omitempty"`
	AvailabilityyImpact        ImpactType                    `json:"availabilityyImpact,omitempty"`
	Exploitability             ExploitabilityType            `json:"exploitability,omitempty"`
	RemediationLevel           RemediationLevelType          `json:"redemdiationLevel,omitempty"`
	ReportConfidence           ConfidenceType                `json:"reportConfidence,omitempty"`
	TemporalScore              float32                       `json:"temporalScore,omitempty"`
	CollateralDamagePotential  CollateralDamagePotentialType `json:"collateralDamagePotential,omitempty"`
	TargetDistribution         TargetDistributionType        `json:"targetDistribution,omitempty"`
	ConfidentialityRequirement CIARequirementType            `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement       CIARequirementType            `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement    CIARequirementType            `json:"availabilityRequirement,omitempty"`
	EnvironmentalScore         float32                       `json:"environmentalScore,omitempty"`
}

type AccessVectorType string

const (
	AccessVectorTypeLOCAL           AccessVectorType = "LOCAL"
	AccessVectorTypeADJACENTNETWORK AccessVectorType = "ADJACENT_NETWORK"
	AccessVectorTypeNETWORK         AccessVectorType = "NETWORK"
)

type AccessComplexityType string

const (
	AccessComplexityTypeLOW    AccessComplexityType = "LOW"
	AccessComplexityTypeMEDIUM AccessComplexityType = "MEDIUM"
	AccessComplexityTypeHIGH   AccessComplexityType = "HIGH"
)

type AuthenticationType string

const (
	AuthenticationTypeNONE     AuthenticationType = "NONE"
	AuthenticationTypeSINGLE   AuthenticationType = "SINGLE"
	AuthenticationTypeMULTIPLE AuthenticationType = "MULTIPLE"
)

type ImpactType string

const (
	ImpactTypeNone ImpactType = "NONE"
	ImpactTypeLow  ImpactType = "PARTIAL"
	ImpactTypeHigh ImpactType = "COMPLETE"
)

type ExploitabilityType string

const (
	ExploitabilityTypeNOTDEFINED     ExploitabilityType = "NOT_DEFINED"
	ExploitabilityTypeUNPROVEN       ExploitabilityType = "UNPROVEN"
	ExploitabilityTypePROOFOFCONCEPT ExploitabilityType = "PROOF_OF_CONCEPT"
	ExploitabilityTypeFUNCTIONAL     ExploitabilityType = "FUNCTIONAL"
	ExploitabilityTypeHIGH           ExploitabilityType = "HIGH"
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
	ConfidenceTypeUNKNOWN    ConfidenceType = "UNCONFIRMED"
	ConfidenceTypeNOTDEFINED ConfidenceType = "NOT_DEFINED"
	ConfidenceTypeREASONABLE ConfidenceType = "UNCORROBORATED"
	ConfidenceTypeCONFIRMED  ConfidenceType = "CONFIRMED"
)

type CollateralDamagePotentialType string

const (
	CollateralDamagePotentialTypeNOTDEFINED CollateralDamagePotentialType = "NOT_DEFINED"
	CollateralDamagePotentialTypeNONE       CollateralDamagePotentialType = "NONE"
	CollateralDamagePotentialTypeLOW        CollateralDamagePotentialType = "LOW"
	CollateralDamagePotentialTypeLOWMEDIUM  CollateralDamagePotentialType = "LOW_MEDIUM"
	CollateralDamagePotentialTypeMEDIUMHIGH CollateralDamagePotentialType = "MEDIUM_HIGH"
	CollateralDamagePotentialTypeHIGH       CollateralDamagePotentialType = "HIGH"
)

type TargetDistributionType string

const (
	TargetDistributionTypeNOTDEFINED TargetDistributionType = "NOT_DEFINED"
	TargetDistributionTypeNONE       TargetDistributionType = "NONE"
	TargetDistributionTypeLOW        TargetDistributionType = "LOW"
	TargetDistributionTypeMEDIUM     TargetDistributionType = "MEDIUM"
	TargetDistributionTypeHIGH       TargetDistributionType = "HIGH"
)

type CIARequirementType string

const (
	CIARequirementTypeNOTDEFINED CIARequirementType = "NOT_DEFINED"
	CIARequirementTypeLOW        CIARequirementType = "LOW"
	CIARequirementTypeMEDIUM     CIARequirementType = "MEDIUM"
	CIARequirementTypeHIGH       CIARequirementType = "HIGH"
)
