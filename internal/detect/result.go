package detect

type Category string

const (
	Language  Category = "language"
	Framework Category = "framework"
	Database  Category = "database"
	Testing   Category = "testing"
	Linting   Category = "linting"
	CI        Category = "ci"
	Bundler   Category = "bundler"
	PkgMgr   Category = "package_manager"
	Runtime   Category = "runtime"
	Infra     Category = "infrastructure"
	Styling   Category = "styling"
)

type Match struct {
	Name       string   `json:"name"`
	Category   Category `json:"category"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}
