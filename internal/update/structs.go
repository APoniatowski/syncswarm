package update

const udpPort int = 64512

// confirmationRequests / expectedResponses form a challenge–response handshake
// modelled on the Warhammer 40k Adeptus Astartes catechism. Each request must be
// answered with the response at the same index:
//
//	WIYD  "What Is Your Duty?"          -> TSEW  "That we Serve the Emperor's Will"
//	WITEW "What Is The Emperor's Will?" -> TWFAD "That We Fight And Die"
//	WID   "What Is Death?"              -> IIOD  "It Is Our Duty"
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
