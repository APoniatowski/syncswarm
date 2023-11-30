package update

const udpPort int = 64512

var (
	confirmationRequests = []string{"WIYD", "WITEW", "WID"}
	expectedResponses    = []string{"TSEW", "TWFAD", "IIOD"}
)

type UpdateService interface {
	SendUpdate(key *string) error
	ReceiveUpdate(key *string) error
}

type NewUpdate struct {
	NewPayload        UpdateService
	NetworkUpdateData NetworkUpdateData
}

type NetworkUpdateData struct {
	Nodes      []string
	Originator string
	NewPubKey  string
	NewPrivKey string
	NewHeader  string
}
