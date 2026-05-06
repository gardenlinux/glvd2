package debtriage

type StatusType string

const (
	StatusUnknown   StatusType = "UNKNOWN"
	StatusToDo      StatusType = "TODO"
	StatusRejected  StatusType = "REJECTED"
	StatusNotForUs  StatusType = "NOT-FOR-US"
	StatusProcessed StatusType = "PROCESSED"
	StatusReserved  StatusType = "RESERVED"
)
