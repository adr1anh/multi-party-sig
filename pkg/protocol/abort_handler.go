package protocol

import (
	"errors"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type AbortMessage struct {
	From        party.ID
	RoundNumber round.Number
	Abort       bool
	Broadcast   []byte
	P2P         map[party.ID][]byte
}

type abortRound struct {
	round    round.Session
	messages map[party.ID]*AbortMessage
	// set of parties who have sent an abort at some point.
	// If the accusal was misleading, the n
	accusations map[party.ID]*abortRound
	culprits    map[party.ID]error
	allVerified bool
}

type AbortHandler struct {
	out          chan *Message
	currentRound *abortRound
	rounds       map[round.Number]*abortRound
	mtx          sync.Mutex // maybe remove?

	err    *Error
	result interface{}
}

// NewAbortHandler expects a StartFunc for the desired protocol. It returns a handler that the user can interact with.
func NewAbortHandler(create StartFunc, sessionID []byte) (*AbortHandler, error) {
	r, err := create(sessionID)
	if err != nil {
		return nil, fmt.Errorf("protocol: failed to create round: %w", err)
	}
	currentRound := &abortRound{
		round:       r,
		messages:    map[party.ID]*AbortMessage{},
		accusations: map[party.ID]*abortRound{},
		culprits:    map[party.ID]error{},
	}
	h := &AbortHandler{
		out:          make(chan *Message, 2*r.N()),
		currentRound: currentRound,
		rounds:       map[round.Number]*abortRound{r.Number(): currentRound},
	}
	h.finalize()
	return h, nil
}

func (h *AbortHandler) Update(msgWrapped *Message) {
	var msg AbortMessage

	if err := cbor.Unmarshal(msgWrapped.Data, &msg); err != nil {
		panic(err)
	}
	h.mtx.Lock()
	defer h.mtx.Unlock()
	//fmt.Println(h.currentRound.round.Number(), h.currentRound.round.SelfID(), msg.From)

	number := msg.RoundNumber
	if h.rounds[number] == nil {
		h.rounds[number] = &abortRound{
			messages:    map[party.ID]*AbortMessage{},
			accusations: map[party.ID]*abortRound{},
			culprits:    map[party.ID]error{},
		}
	}
	r := h.rounds[number]
	if msg.Abort {
		// we already detected culprits, so we ignore this message
		if len(r.culprits) != 0 {
			return
		}

		h.currentRound.accusations[msg.From] = r
		return
	}
	r.store(&msg)
	h.finalize()
}

func (h *AbortHandler) finalize() {
	for {
		if h.err != nil || h.result != nil {
			return
		}
		if !h.currentRound.receivedAll() {
			return
		}
		nextMsg, nextRound := h.currentRound.finalize()
		if nextMsg != nil {
			buf, _ := cbor.Marshal(nextMsg)
			h.out <- &Message{
				From:        nextMsg.From,
				RoundNumber: nextMsg.RoundNumber,
				Data:        buf,
				Broadcast:   true,
			}
		}
		if nextRound != nil {
			if outputRound, ok := nextRound.(*round.Output); ok {
				h.result = outputRound.Result
				close(h.out)
				return
			}

			if h.rounds[nextRound.Number()] == nil {
				h.rounds[nextRound.Number()] = &abortRound{
					round:       nextRound,
					messages:    map[party.ID]*AbortMessage{},
					accusations: map[party.ID]*abortRound{},
					culprits:    map[party.ID]error{},
				}
			}
			h.currentRound = h.rounds[nextRound.Number()]
			h.currentRound.round = nextRound
			h.currentRound.handleQueue()

		} else {
			// we aborted
			h.err = &Error{
				Err: errors.New(fmt.Sprintf("%v", h.currentRound.culprits)),
			}
			close(h.out)
			return
		}
	}
}

func (r *abortRound) receivedAll() bool {
	if r == nil || r.round == nil || r.messages == nil {
		return false
	}
	if r.round.Number() == 1 {
		return true
	}
	for _, id := range r.round.OtherPartyIDs() {
		if r.messages[id] == nil && r.accusations[id] == nil {
			return false
		}
	}
	return true
}

func (r *abortRound) store(msg *AbortMessage) {
	// create messages if the struct does not exist
	if r.messages == nil {
		r.messages = map[party.ID]*AbortMessage{}
	}

	// simply ignore duplicate, as well as messages from parties who have accused
	if r.messages[msg.From] != nil || r.accusations[msg.From] != nil {
		return
	}
	r.messages[msg.From] = msg

	// if the round is already here, we can handle the message
	if r.round != nil {
		r.handleMessage(msg)
	}
}

func (r *abortRound) handleQueue() {
	for _, msg := range r.messages {
		r.handleMessage(msg)
	}
}

func (r *abortRound) handleMessage(msg *AbortMessage) {
	//stop handling messages if we got an accusation
	if len(r.accusations) != 0 {
		return
	}

	if b, ok := r.round.(round.BroadcastRound); ok {
		roundMsg := round.Message{
			From:      msg.From,
			Broadcast: true,
			Content:   b.BroadcastContent(),
		}
		if err := cbor.Unmarshal(msg.Broadcast, roundMsg.Content); err != nil {
			r.culprits[msg.From] = err
			return
		}
		if err := b.StoreBroadcastMessage(roundMsg); err != nil {
			r.culprits[msg.From] = err
			return
		}
	}
	// exit if the round does not expect any P2P messages.
	if r.round.MessageContent() == nil {
		return
	}

	// check that all P2P messages are present
	if len(msg.P2P) == 0 {
		fmt.Println("abort")
		r.culprits[msg.From] = errors.New("message did not contain P2P messages")
		return
	}
	for _, id := range r.round.PartyIDs().Remove(msg.From) {
		if msg.P2P[id] == nil {
			fmt.Println("abort")
			r.culprits[msg.From] = errors.New("P2P message did not contain messages for all parties")
			return
		}
	}

	roundMsg := round.Message{
		From:    msg.From,
		To:      r.round.SelfID(),
		Content: r.round.MessageContent(),
	}
	if err := cbor.Unmarshal(msg.P2P[r.round.SelfID()], roundMsg.Content); err != nil {
		fmt.Println("abort")
		r.culprits[msg.From] = err
		return
	}
	if err := r.round.VerifyMessage(roundMsg); err != nil {
		fmt.Println("abort")
		r.culprits[msg.From] = err
	}
	if err := r.round.StoreMessage(roundMsg); err != nil {
		fmt.Println("abort")
		r.culprits[msg.From] = err
	}
}

func (r *abortRound) verifyAllMessages() {
	if r.round == nil || r.allVerified {
		return
	}

	checkedAll := true
	if r.round.MessageContent() != nil {
		for _, sender := range r.round.OtherPartyIDs() {
			// don't re-verify the messages of the culprits, or the parties who sent an abort
			if r.culprits[sender] != nil || r.accusations[sender] != nil {
				continue
			}
			// don't look at the messages from
			if r.messages[sender] == nil {
				checkedAll = false
				continue
			}
			for recipient, msg := range r.messages[sender].P2P {
				roundMsg := round.Message{
					From:    sender,
					To:      recipient,
					Content: r.round.MessageContent(),
				}
				if err := cbor.Unmarshal(msg, roundMsg.Content); err != nil {
					r.culprits[sender] = err
					continue
				}
				if err := r.round.VerifyMessage(roundMsg); err != nil {
					r.culprits[sender] = err
					continue
				}
			}
		}
	}
	if checkedAll {
		r.allVerified = true
	}
}

// finalize should be called only if abortRound.receivedAll is true.
// If an AbortMessage is returned, it must be sent out to all users.
// If the round returned is nil, then the handler should stop executing,
// and return as error the list of culprits detected.
func (r *abortRound) finalize() (*AbortMessage, round.Session) {
	// we have received a message from everyone, but some participants decided to abort,
	// we need to return early, but first check all claims
	if len(r.accusations) != 0 {
		for accuser, accusationRound := range r.accusations {
			accusationRound.verifyAllMessages()
			if len(accusationRound.culprits) == 0 {
				fmt.Println("abort")
				r.culprits[accuser] = errors.New("incorrect accusation")
			}
		}
		return nil, nil
	}

	// check if we can detect some culprits normally
	if identifiableAbortRound, ok := r.round.(round.IdentifiableAbortRound); ok {
		culprits := identifiableAbortRound.IdentifyCulprits()
		for _, culprit := range culprits {
			if r.culprits[culprit] == nil {
				r.culprits[culprit] = errors.New("identified")
			}
		}
	}

	// if we have some culprits, we need to check all messages
	if len(r.culprits) != 0 {
		r.verifyAllMessages()

		return &AbortMessage{
			From:        r.round.SelfID(),
			RoundNumber: r.round.Number(),
			Abort:       true,
		}, nil
	}

	// normally, we didn't get any culprits, at least for the messages intended for us,
	// so it's safe to finalize
	out := make(chan *round.Message, r.round.N()+1)
	nextRound, err := r.round.Finalize(out)
	close(out)
	if err != nil {
		// todo check what should really happen
		panic(err)
	}

	// we can exit here because we don't have anymore messages to send
	if len(out) == 0 {
		return nil, nextRound
	}

	// by now, we know that there aren't any culprits
	msg := &AbortMessage{
		From:        r.round.SelfID(),
		RoundNumber: nextRound.Number(),
		P2P:         map[party.ID][]byte{},
	}
	for roundMsg := range out {
		if roundMsg.Broadcast {
			if msg.Broadcast, err = cbor.Marshal(roundMsg.Content); err != nil {
				// todo
				panic(err)
			}
		} else {
			if msg.P2P[roundMsg.To], err = cbor.Marshal(roundMsg.Content); err != nil {
				// todo
				panic(err)
			}
		}
	}
	return msg, nextRound
}

// Result returns the protocol result if the protocol completed successfully. Otherwise an error is returned.
func (h *AbortHandler) Result() (interface{}, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.result != nil {
		return h.result, nil
	}
	if h.err != nil {
		return nil, *h.err
	}
	return nil, errors.New("protocol: not finished")
}

// Listen returns a channel with outgoing messages that must be sent to other parties.
// The message received should be _reliably_ broadcast if msg.Broadcast is true.
// The channel is closed when either an error occurs or the protocol detects an error.
func (h *AbortHandler) Listen() <-chan *Message {
	return h.out
}

func (h *AbortHandler) String() string {
	return fmt.Sprintf("party: %s, protocol: %s", h.currentRound.round.SelfID(), h.currentRound.round.ProtocolID())
}
