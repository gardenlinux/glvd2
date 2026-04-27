//nolint:tagliatelle // schema not defined by us
package cve_v5

import (
	"time"

	"github.com/gardenlinux/glvd2/internal/model/cvss_v2_0"
	"github.com/gardenlinux/glvd2/internal/model/cvss_v3_x"
	"github.com/gardenlinux/glvd2/internal/model/cvss_v4_0"
	"github.com/google/uuid"
)

type CVEV5 struct {
	DataType    string     `json:"dataType"`
	DataVersion string     `json:"dataVersion"`
	Metadata    Metadata   `json:"cveMetadata"`
	Containers  Containers `json:"containers"`
}

type StateType string

const (
	StatePublished StateType = "PUBLISHED"
	StateRejected  StateType = "REJECTED"
)

type Metadata struct {
	ID            string    `json:"cveId"`
	OrgID         uuid.UUID `json:"assignerOrgId"`
	DateUpdated   time.Time `json:"dateUpdated"`
	DatePublished time.Time `json:"datePublished"`
	Serial        int       `json:"serial,omitempty"`
	State         StateType `json:"state"`
}

type Containers struct {
	CNAContainer CNAContainer   `json:"cna"`
	ADPContainer []ADPContainer `json:"adp,omitempty"`
}

type CNAContainer struct {
	ProviderMetadata ProviderMetadata `json:"providerMetadata"`
	DatePublic       time.Time        `json:"datePublic"`
	Title            string           `json:"title"`
	Descriptions     []Description    `json:"descriptions"`
	Affected         []Affected       `json:"affected"`
	Metrics          []Metric         `json:"metrics,omitempty"`
	Configurations   []Description    `json:"configurations,omitempty"`
	Workarounds      []Description    `json:"workarounds,omitempty"`
	Solutions        []Description    `json:"solutions,omitempty"`
	Exploits         []Description    `json:"exploits,omitempty"`
	Timeline         []TimelineEntry  `json:"timeline,omitempty"`
	Tags             []string         `json:"tags,omitempty"`
}

type ADPContainer struct {
	ProviderMetadata ProviderMetadata `json:"providerMetadata"`
	DatePublic       *time.Time       `json:"datePublic,omitempty"`
	Title            string           `json:"title,omitempty"`
	Descriptions     []Description    `json:"descriptions,omitempty"`
	Affected         []Affected       `json:"affected,omitempty"`
	Metrics          []Metric         `json:"metrics,omitempty"`
	Configurations   []Description    `json:"configurations,omitempty"`
	Workarounds      []Description    `json:"workarounds,omitempty"`
	Solutions        []Description    `json:"solutions,omitempty"`
	Exploits         []Description    `json:"exploits,omitempty"`
	Timeline         []TimelineEntry  `json:"timeline,omitempty"`
	Tags             []string         `json:"tags,omitempty"`
}

type ProviderMetadata struct {
	OrgID     uuid.UUID `json:"orgId"`
	ShortName string    `json:"shortName,omitempty"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Affected struct {
	Vendor          string            `json:"vendor,omitempty"`
	Product         string            `json:"product,omitempty"`
	CollectionURL   string            `json:"collectionURL,omitempty"` // TODO: can be debian related
	PackageName     string            `json:"packageName,omitempty"`   // TODO: see collection url
	Platforms       []string          `json:"platforms,omitempty"`
	Repo            string            `json:"repo,omitempty"`
	CPEs            []string          `json:"cpes,omitempty"`
	Modules         []string          `json:"modules,omitempty"`
	ProgramFiles    []string          `json:"programFiles,omitempty"`
	ProgramRoutines []ProgramRoutine  `json:"programRoutines,omitempty"`
	Versions        []Version         `json:"versions,omitempty"`
	DefaultStatus   VersionStatusType `json:"defaultStatus,omitempty"`
}

type ProgramRoutine struct {
	Name string `json:"name"`
}

type VersionStatusType string

const (
	StatusAffected   VersionStatusType = "affected"
	StatusUnaffected VersionStatusType = "unaffected"
	StatusUnknown    VersionStatusType = "unknown"
)

type VersionStatusChange struct {
	At     string            `json:"at"`
	Status VersionStatusType `json:"status"`
}

// Version: not all fields are present at the same time (one of relation).
type Version struct {
	Version         string                `json:"version"`
	Status          VersionStatusType     `json:"status,omitempty"`
	VersionType     string                `json:"versionType,omitempty"`
	LessThan        string                `json:"lessThan,omitempty"`
	LessThanOrEqual string                `json:"lessThanOrEqual,omitempty"`
	Changes         []VersionStatusChange `json:"changes,omitempty"`
}

type Metric struct {
	Format    string              `json:"format,omitempty"`
	Scenarios []Scenario          `json:"scenarios,omitempty"`
	CVSSV4_0  *cvss_v4_0.CVSSV4_0 `json:"cvssV4_0,omitempty"`
	CVSSV3_1  *cvss_v3_x.CVSSV3_x `json:"cvssV3_1,omitempty"`
	CVSSV3_0  *cvss_v3_x.CVSSV3_x `json:"cvssV3_0,omitempty"`
	CVSSV2_0  *cvss_v2_0.CVSSV2_0 `json:"cvssV2_0,omitempty"`
	Other     any                 `json:"other,omitempty"`
}

type Scenario struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type TimelineEntry struct {
	Time  time.Time `json:"time"`
	Lang  string    `json:"lang"`
	Value string    `json:"value"`
}
