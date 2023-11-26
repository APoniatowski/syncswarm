package update

const udpPort int = 64512

var (
	confirmationRequests = []string{"WIYD", "WITEW", "WID"}
	expectedResponses    = []string{"TSEW", "TWFAD", "IIOD"}
)

type NetworkUpdateData struct {
	Nodes      []string
	Originator string
	NewPubKey  string
	NewPrivKey string
}
