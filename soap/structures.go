package soap

import (
	"encoding/xml"
	"time"
)

// Common SAP structures
type SAPInstance struct {
	Hostname      string `xml:"hostname"`
	InstanceNr    string `xml:"instanceNr"`
	SystemID      string `xml:"systemId"`
	HttpPort      string `xml:"httpPort"`
	HttpsPort     string `xml:"httpsPort"`
	StartPriority string `xml:"startPriority"`
	Features      string `xml:"features"`
	Dispstatus    string `xml:"dispstatus"`
	Sapstatus     string `xml:"sapstatus"`
	StatusText    string `xml:"statustext"`
}

type GetSystemInstanceList struct {
	XMLName xml.Name `xml:"urn:SAPControl GetSystemInstanceList"`
}

type SAPInstanceList struct {
	XMLName  xml.Name      `xml:"urn:SAPControl"`
	Instance []SAPInstance `xml:"instance"`
}

// Dispatcher structures
type GetWPTable struct {
	XMLName xml.Name `xml:"urn:SAPControl GetWPTable"`
}

type WPTable struct {
	XMLName     xml.Name      `xml:"urn:SAPControl"`
	Workprocess []WorkProcess `xml:"workprocess"`
}

type WorkProcess struct {
	No      string `xml:"No"`
	Type    string `xml:"Typ"`
	Pid     string `xml:"Pid"`
	Status  string `xml:"Status"`
	Reason  string `xml:"Reason"`
	Start   string `xml:"Start"`
	Err     string `xml:"Err"`
	Sem     string `xml:"Sem"`
	Cpu     string `xml:"Cpu"`
	Time    string `xml:"Time"`
	Program string `xml:"Program"`
	Client  string `xml:"Client"`
	User    string `xml:"User"`
	Action  string `xml:"Action"`
	Table   string `xml:"Table"`
}

type GetQueueStatistic struct {
	XMLName xml.Name `xml:"urn:SAPControl GetQueueStatistic"`
}

type QueueStatistic struct {
	XMLName xml.Name     `xml:"urn:SAPControl"`
	Queue   []QueueEntry `xml:"queue"`
}

type QueueEntry struct {
	Typ    string `xml:"Typ"`
	Now    int    `xml:"Now"`
	High   int    `xml:"High"`
	Max    int    `xml:"Max"`
	Writes int    `xml:"Writes"`
	Reads  int    `xml:"Reads"`
}

// Enqueue structures
type GetEnqTable struct {
	XMLName xml.Name `xml:"urn:SAPControl GetEnqTable"`
}

type EnqTable struct {
	XMLName xml.Name   `xml:"urn:SAPControl"`
	Lock    []EnqLock  `xml:"lock"`
	Summary EnqSummary `xml:"summary"`
}

type EnqLock struct {
	LockName    string `xml:"LockName"`
	TableName   string `xml:"TableName"`
	Client      string `xml:"Client"`
	User        string `xml:"User"`
	Transaction string `xml:"Transaction"`
	Obj         string `xml:"Obj"`
	Mode        string `xml:"Mode"`
	Owner       string `xml:"Owner"`
	OwnerVb     string `xml:"OwnerVb"`
	Count       string `xml:"Count"`
	Backup      string `xml:"Backup"`
}

type EnqSummary struct {
	Locks   int `xml:"Locks"`
	Owners  int `xml:"Owners"`
	Entries int `xml:"Entries"`
	Used    int `xml:"Used"`
	Max     int `xml:"Max"`
}

// Response wrapper
type Response struct {
	Data     interface{}
	Error    error
	Time     time.Time
	Instance string
}
