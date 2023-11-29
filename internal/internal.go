package internal

type CurrentData struct {
	Nodes        *[]string
	Progenitor   *string
	Successor    *string
	Hostname     *string
	PubKey       *string
	PrivKey      *string
	PreSharedKey *string
}
