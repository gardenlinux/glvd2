package publish

// Level controls how far publishing goes; each step includes the previous.
type Level int

const (
	LevelNone   Level = iota // generate artifacts only; no git actions (default)
	LevelCommit              // commit each group locally; no push
	LevelPush                // commit locally, then fast-forward push
)

func (l Level) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelCommit:
		return "commit"
	case LevelPush:
		return "push"
	default:
		return "unknown"
	}
}

// ParseLevel maps a string to a Level, returning false for unknown values.
func ParseLevel(s string) (Level, bool) {
	switch s {
	case "none":
		return LevelNone, true
	case "commit":
		return LevelCommit, true
	case "push":
		return LevelPush, true
	default:
		return 0, false
	}
}
