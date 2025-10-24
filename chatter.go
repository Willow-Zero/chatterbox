// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	//	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	"fmt" //un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}
	// zeroize session elements
	c.Sessions[*partnerIdentity].MyDHRatchet.Zeroize()
	c.Sessions[*partnerIdentity].RootChain.Zeroize()
	c.Sessions[*partnerIdentity].SendChain.Zeroize()
	c.Sessions[*partnerIdentity].ReceiveChain.Zeroize()
	// TODO: your code here to zeroize remaining state

	delete(c.Sessions, *partnerIdentity)

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}
    ephemeralKey := GenerateKeyPair()
    
    c.Sessions[*partnerIdentity] = &Session{
        CachedReceiveKeys: make(map[int]*SymmetricKey),
        MyDHRatchet:       ephemeralKey,
        SendCounter:       0,
        LastUpdate:        0,
        ReceiveCounter:    0,
    }
	return &ephemeralKey.PublicKey, nil
	// TODO: your code here

	return nil, errors.New("InitiateHandshake not implemented")
}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
    partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

    if _, exists := c.Sessions[*partnerIdentity]; exists {
        return nil, nil, errors.New("Already have session open")
    }
    
    myEphemeral := GenerateKeyPair()
    
    // 3 secrets
    dh1 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)           // partner_ephemeral * my_identity
    dh2 := DHCombine(partnerIdentity, &myEphemeral.PrivateKey)           // partner_identity * my_ephemeral
    dh3 := DHCombine(partnerEphemeral, &myEphemeral.PrivateKey)          // partner_ephemeral * my_ephemeral

    // DH outputs to form key
    rootKey := CombineKeys(dh2, dh1, dh3)
    handshakeCheck := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

    c.Sessions[*partnerIdentity] = &Session{
        CachedReceiveKeys: make(map[int]*SymmetricKey),
        MyDHRatchet:       myEphemeral,
        PartnerDHRatchet:  partnerEphemeral.Duplicate(),
        RootChain:         rootKey,
        SendCounter:       0,
        LastUpdate:        0,
        ReceiveCounter:    0,
    }

    return &myEphemeral.PublicKey, handshakeCheck, nil
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake.The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {
		session, exists := c.Sessions[*partnerIdentity]
		if !exists {
			return nil, errors.New("Can't finalize session, not yet open")
		}
		
    // compute the shared secrets
    // these should match what the responder computed
    dh1 := DHCombine(partnerIdentity, &session.MyDHRatchet.PrivateKey)   // partner_identity * my_ephemeral  
    dh2 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)           // partner_ephemeral * my_identity
    dh3 := DHCombine(partnerEphemeral, &session.MyDHRatchet.PrivateKey)  // partner_ephemeral * my_ephemeral

    // combine all three outputs
    rootKey := CombineKeys(dh2, dh1, dh3)
    handshakeCheck := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

    session.PartnerDHRatchet = partnerEphemeral.Duplicate()
    session.RootChain = rootKey
    session.SendChain = nil
    session.ReceiveChain = nil

    return handshakeCheck, nil

	return nil, errors.New("FinalizeHandshake not implemented")
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {
		session, exists := c.Sessions[*partnerIdentity]
		if !exists {
			return nil, errors.New("Can't send message to partner with no open session")
		}
	
		// initialize send chain if this is the first message
		if session.SendChain == nil {
			session.SendChain = session.RootChain.DeriveKey(CHAIN_LABEL)
			// fmt.Printf("DE8UG send: initialized send ch8n: %x\n", session.SendChain.Key[:8])
		}
		ratchetFlag := false
		// increment counter and derive message key
		messageKey := session.SendChain.DeriveKey(KEY_LABEL)
		//if session.SendCounter%3 == 1{
		//	ratchetFlag = true
		//	session.SendChain = nil
		//} else{
		session.SendChain = session.SendChain.DeriveKey(CHAIN_LABEL)
		//}
		//fmt.Printf("DE8UG send: Counter=%d",session.SendCounter)
		session.SendCounter++
	
		//fmt.Printf("DE8UG send: Counter=%d, MessageKey=%x\n", c.Sessions[*partnerIdentity].SendCounter, messageKey.Key[:8])
	
		// gener8te IV
		iv := NewIV()
	
		// cre8te message
		message := &Message{
			Sender:        &c.Identity.PublicKey,
			Receiver:      partnerIdentity,
			NextDHRatchet: nil, 
			Counter:       session.SendCounter,
			LastUpdate:    session.LastUpdate,
			IV:            iv,
		}
		if ratchetFlag{
			session.LastUpdate++
			
		}

		
		// encode additional d8a and encrypt
		additionalData := message.EncodeAdditionalData()
		ciphertext := messageKey.AuthenticatedEncrypt(plaintext, additionalData, iv)
		message.Ciphertext = ciphertext
	
		return message, nil
	return message, errors.New("SendMessage not implemented")
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {
	session, exists := c.Sessions[*message.Sender]
    if !exists {
        return "", errors.New("Can't receive message from partner with no open session")
    }

    // handle dh ratchet if present
    if message.NextDHRatchet != nil {
        // fmt.Printf("DEBUG Receive: Performing DH ratchet\n")
        // compute new dh secret
        dhSecret := DHCombine(message.NextDHRatchet, &session.MyDHRatchet.PrivateKey)
        
        // upd8e root chain
        session.RootChain = CombineKeys(session.RootChain, dhSecret)
        session.PartnerDHRatchet = message.NextDHRatchet.Duplicate()
        
        // initialize receive chain from new root
        session.ReceiveChain = session.RootChain.DeriveKey(CHAIN_LABEL)
        
        // upd8te counters
        session.LastUpdate = message.Counter
        session.ReceiveCounter = 0
        
        // fmt.Printf("DE8UG Receive: DH ratchet - new root: %x, receive chain: %x\n", session.RootChain.Key[:8], session.ReceiveChain.Key[:8])

    }

    if session.ReceiveChain == nil {
        session.ReceiveChain = session.RootChain.DeriveKey(CHAIN_LABEL)
        // fmt.Printf("DE8UG Receive: First message - initialized receive chain: %x\n", session.ReceiveChain.Key[:8])
    }

    // fmt.Printf("DE8UG Receive: Counter=%d, ReceiveChain=%x\n", message.Counter, session.ReceiveChain.Key[:8])

    // handle out-of-order messages
    if message.Counter <= session.ReceiveCounter {
        // fmt.Printf("DEBUG Receive: Out-of-order message, counter=%d, expected=%d\n", message.Counter, session.ReceiveCounter)
        if key, exists := session.CachedReceiveKeys[message.Counter]; exists {
            additionalData := message.EncodeAdditionalData()
            plaintext, err := key.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)
            if err != nil {
                return "", fmt.Errorf("authentication failed for cached message %d: %v", message.Counter, err)
            }
            delete(session.CachedReceiveKeys, message.Counter)
            return plaintext, nil
        }
        return "", fmt.Errorf("duplicate or invalid message counter: %d", message.Counter)
    }

    // new message - derive keys and decrypt
    currentChain := session.ReceiveChain.Duplicate()
    
    // cache keys for skipped messages
    for i := session.ReceiveCounter + 1; i < message.Counter; i++ {
        skippedKey := currentChain.DeriveKey(KEY_LABEL)
        session.CachedReceiveKeys[i] = skippedKey
        currentChain = currentChain.DeriveKey(CHAIN_LABEL)
    }

    // derive key for this message
    messageKey := currentChain.DeriveKey(KEY_LABEL)
    
    // upd8 receive chain
    session.ReceiveChain = currentChain.DeriveKey(CHAIN_LABEL)
    session.ReceiveCounter = message.Counter

    // fmt.Printf("DEBUG Receive: Derived message key: %x\n", messageKey.Key[:8])

    // decrypt
    additionalData := message.EncodeAdditionalData()
    plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)
    if err != nil {
        return "", fmt.Errorf("authentication failed: %v", err)
    }

    return plaintext, nil

	return "", errors.New("RecieveMessage not implemented")
}
