package transfer

import "errors"

// Sentinel errors for send outcomes, so callers can branch with errors.Is instead
// of matching on message text.
//
// The distinction that matters to an application is whether anything left the
// device, because it decides what to tell a user and whether re-sending is safe:
//
//   - ErrDestinationUnreachable and ErrNoAnonymousRoute are returned *before any
//     fragment is emitted*. Nothing was sent; re-sending is correct.
//   - ErrNotConfirmed means fragments went out and no acknowledgement came back.
//     A relay running store-and-forward may still be holding and retrying them, so
//     re-sending risks the recipient seeing the message twice.
//
// The wrapped messages are unchanged, so existing text matching keeps working; the
// point is that it no longer has to.
var (
	// ErrDestinationUnreachable: the destination is neither active nor reachable
	// through a live circuit reservation. Returned before anything is sent.
	ErrDestinationUnreachable = errors.New("destination not reachable")

	// ErrNoAnonymousRoute: StrictAnonymity is set and no relay path with the
	// required diversity exists. Returned before anything is sent, deliberately, in
	// preference to falling back to a direct connection.
	ErrNoAnonymousRoute = errors.New("no anonymous route")

	// ErrNotConfirmed: fragments were sent but no end-to-end acknowledgement
	// arrived within the attempt budget. The transfer may still be in flight or
	// held by a store-and-forward relay.
	ErrNotConfirmed = errors.New("delivery not confirmed")
)
