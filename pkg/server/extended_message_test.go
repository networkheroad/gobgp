package server

import (
	"context"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// disableExtendedMessageOpt opts a neighbour out of advertising the
// RFC 8654 Extended Message Capability. The DisableExtendedMessage
// knob carries inverted polarity (zero = advertise per Section 5),
// so opting out means flipping it to true.
func disableExtendedMessageOpt(_ *BgpServer, _ *oc.Global, p *oc.Neighbor) {
	p.Config.DisableExtendedMessage = true
}

// remoteAdvertisedExtendedMessage walks a peer's remote capability
// list looking for *bgp.CapExtendedMessage. It is the on-wire
// observation of what the peer sent in its OPEN message, which is
// the only signal a test has of the negotiation outcome.
func remoteAdvertisedExtendedMessage(p *api.Peer) bool {
	if p == nil || p.State == nil {
		return false
	}
	for _, c := range p.State.RemoteCap {
		if c == nil {
			continue
		}
		if c.GetExtendedMessage() != nil {
			return true
		}
	}
	return false
}

// localAdvertisedExtendedMessage mirrors remoteAdvertisedExtendedMessage
// on the local capability list - that is, what WE put in the OPEN.
func localAdvertisedExtendedMessage(p *api.Peer) bool {
	if p == nil || p.State == nil {
		return false
	}
	for _, c := range p.State.LocalCap {
		if c == nil {
			continue
		}
		if c.GetExtendedMessage() != nil {
			return true
		}
	}
	return false
}

// TestExtendedMessage_NegotiatedWhenBothAdvertise covers the happy
// path of RFC 8654 Section 4: both peers advertise the capability,
// so the negotiation succeeds and each side carries the capability
// on both its local and the peer's remote capability lists.
func TestExtendedMessage_NegotiatedWhenBothAdvertise(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s1 := runNewServer(t, 64512, "1.1.1.1", 10179)
	defer s1.StopBgp(ctx, &api.StopBgpRequest{})
	s2 := runNewServer(t, 64512, "2.2.2.2", 20179)
	defer s2.StopBgp(ctx, &api.StopBgpRequest{})

	require.NoError(t, peerServers(t, ctx, []*BgpServer{s1, s2},
		[]oc.AfiSafiType{oc.AFI_SAFI_TYPE_IPV4_UNICAST}))

	newPeerStateWaiter(s1, api.PeerState_SESSION_STATE_ESTABLISHED).Wait(t, 20*time.Second)

	checked := false
	require.NoError(t, s1.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		checked = true
		assert.True(t, localAdvertisedExtendedMessage(p),
			"s1 must advertise the capability when DisableExtendedMessage is left at the zero value")
		assert.True(t, remoteAdvertisedExtendedMessage(p),
			"s2 must advertise back when its DisableExtendedMessage is also at the zero value")
	}))
	assert.True(t, checked, "ListPeer must have surfaced an established peer")
}

// TestExtendedMessage_NotNegotiatedWhenOnlyOneSideAdvertises covers
// the asymmetric case from RFC 8654 Section 4: only one side
// advertises the capability, so even though one side knows it can
// handle Extended Messages, the other did not opt in, and neither
// side may send a message above 4096 octets.
func TestExtendedMessage_NotNegotiatedWhenOnlyOneSideAdvertises(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s1 := runNewServer(t, 64512, "1.1.1.1", 10179)
	defer s1.StopBgp(ctx, &api.StopBgpRequest{})
	s2 := runNewServer(t, 64512, "2.2.2.2", 20179)
	defer s2.StopBgp(ctx, &api.StopBgpRequest{})

	// s1 keeps the default (advertises); s2 explicitly disables the
	// capability on every peer it adds. The peer-option hook is set
	// up so the s1 -> s2 peer entry on s1 still defaults to true,
	// but the s2 -> s1 peer entry on s2 has it false. After OPEN, s2
	// does not advertise to s1 even though s1 advertised to s2.
	// Peer the two servers asymmetrically: s1 keeps the default
	// (advertises the capability) and s2 opts out via the peer-option
	// hook. Calling peerTwoServers directly avoids peerServers's
	// symmetric application of opts to both directions.
	families := []oc.AfiSafiType{oc.AFI_SAFI_TYPE_IPV4_UNICAST}
	require.NoError(t, peerTwoServers(t, ctx, s1, s2, families, true /* passive */))
	require.NoError(t, peerTwoServers(t, ctx, s2, s1, families, false, disableExtendedMessageOpt))

	newPeerStateWaiter(s1, api.PeerState_SESSION_STATE_ESTABLISHED).Wait(t, 20*time.Second)

	checked := false
	require.NoError(t, s1.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		checked = true
		// s1 still advertises (default true on its side because the
		// peer option only flips s2's neighbour entries).
		assert.True(t, localAdvertisedExtendedMessage(p),
			"s1 still advertises the capability locally")
		// s2 did not advertise, so the remote list must not carry it.
		assert.False(t, remoteAdvertisedExtendedMessage(p),
			"s2 must not advertise the capability when disabled")
	}))
	assert.True(t, checked, "ListPeer must have surfaced an established peer")
}

// TestExtendedMessage_CapMarshalRoundTripsThroughApi covers the
// apiutil glue: a remote capability list containing
// *bgp.CapExtendedMessage must serialise to api.Capability_ExtendedMessage
// and back without losing identity. Without the dispatch case the
// ListPeer plumbing (which is the only way an operator inspects
// negotiated caps over gRPC) would surface the capability as
// CapUnknown.
func TestExtendedMessage_CapMarshalRoundTripsThroughApi(t *testing.T) {
	// Compose the same shape the FSM stores after OPEN-received:
	// a slice of *bgp.ParameterCapabilityInterface where one
	// element is the empty-TLV Extended Message capability.
	caps := []bgp.ParameterCapabilityInterface{
		bgp.NewCapExtendedMessage(),
	}

	apiCaps, err := apiutil.MarshalCapabilities(caps)
	require.NoError(t, err)
	require.Len(t, apiCaps, 1)
	require.NotNil(t, apiCaps[0].GetExtendedMessage(),
		"the api.Capability oneof must carry the ExtendedMessage variant")

	roundTripped, err := apiutil.UnmarshalCapabilities(apiCaps)
	require.NoError(t, err)
	require.Len(t, roundTripped, 1)
	_, ok := roundTripped[0].(*bgp.CapExtendedMessage)
	require.True(t, ok, "round-trip must preserve the native cap type")
}
