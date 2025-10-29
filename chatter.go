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
	IdentityFlag      int
	UpdateCounter	  int
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
		UpdateCounter:	   0,
        IdentityFlag:      1,
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
		UpdateCounter:	   0,
        ReceiveCounter:    0,
		IdentityFlag:	   0,
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
 const DEBUG = false

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {
		session, exists := c.Sessions[*partnerIdentity]
		if !exists {
			return nil, errors.New("Can't send message to partner with no open session")
		}


		if session.ReceiveChain == nil {
			session.ReceiveChain = session.RootChain.DeriveKey(CHAIN_LABEL)
			// fmt.Printf("DE8UG Receive: First message - initialized receive chain: %x\n", session.ReceiveChain.Key[:8])
		}

		ratchetFlag := false || (session.UpdateCounter%2==session.IdentityFlag)
		//var newDHRKey *PublicKey = nil
		if ratchetFlag{
			session.RootChain = session.RootChain.DeriveKey(ROOT_LABEL)
			newDHPair := GenerateKeyPair()
			//newDHRKey := &newDHPair.PublicKey
			newDHRSecret := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet,&newDHPair.PrivateKey)
			session.RootChain = CombineKeys(session.RootChain,newDHRSecret)
			session.SendChain = session.RootChain.DeriveKey(CHAIN_LABEL)
			session.RootChain = session.RootChain.DeriveKey(ROOT_LABEL)
			session.MyDHRatchet = newDHPair
			session.UpdateCounter++
			session.LastUpdate = session.SendCounter+1
			
			//if DEBUG{fmt.Println("RATCHET")}
			//fmt.Printf("\nSENDING::: Root Chain: %x, Send Chain: %x, Recieve Chain: %x",session.RootChain,session.SendChain,session.ReceiveChain)
		}

		if session.SendChain == nil {
			session.SendChain = session.RootChain.DeriveKey(CHAIN_LABEL)
		}
		messageKey := session.SendChain.DeriveKey(KEY_LABEL)


		session.SendChain = session.SendChain.DeriveKey(CHAIN_LABEL)

	
		session.SendCounter++
	
		// gener8te IV
		iv := NewIV()
	
		// cre8te message
		message := &Message{
			Sender:        &c.Identity.PublicKey,
			Receiver:      partnerIdentity,
			NextDHRatchet: &session.MyDHRatchet.PublicKey, 
			Counter:       session.SendCounter,
			LastUpdate:    session.LastUpdate,
			IV:            iv,
		}
		if DEBUG{
			//fmt.Printf("SEND:    %x\n         %x\n",messageKey.String()[100:],session.RootChain.String()[100:])
		}
		// encode additional d8a and encrypt
		additionalData := message.EncodeAdditionalData()
		ciphertext := messageKey.AuthenticatedEncrypt(plaintext, additionalData, iv)
		message.Ciphertext = ciphertext
		messageKey.Zeroize()
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
	newroot := session.RootChain
	newRecChain := session.ReceiveChain


    // handle dh ratchet if present (this can on ly  be done for on time messages for Reasons)
    if message.Counter == message.LastUpdate && message.Counter == session.ReceiveCounter+1{
		session.UpdateCounter++
		newroot = session.RootChain.DeriveKey(ROOT_LABEL)
		newDHRKey := message.NextDHRatchet
		newDHRSecret := DHCombine(newDHRKey,&session.MyDHRatchet.PrivateKey)
		session.PartnerDHRatchet = newDHRKey.Duplicate()
		newroot = CombineKeys(newroot,newDHRSecret)
		newRecChain = newroot.DeriveKey(CHAIN_LABEL)
		newroot = newroot.DeriveKey(ROOT_LABEL)
		//fmt.Printf("\nRECIEVING::: Root Chain: %x, Send Chain: %x, Recieve Chain: %x",session.RootChain,session.SendChain,session.ReceiveChain)

    }

    if newRecChain == nil {
        newRecChain = newroot.DeriveKey(CHAIN_LABEL)
        // fmt.Printf("DE8UG Receive: First message - initialized receive chain: %x\n", session.ReceiveChain.Key[:8])
    }

    // fmt.Printf("DE8UG Receive: Counter=%d, ReceiveChain=%x\n", message.Counter, session.ReceiveChain.Key[:8])

    // handle out-of-order messages
	if message.Counter-1 > session.ReceiveCounter{
		if DEBUG{fmt.Printf("DE8UG: %d recieving early message\n",session.IdentityFlag)}
		for message.Counter > session.ReceiveCounter+1{
			session.ReceiveCounter++
			if session.ReceiveCounter == message.LastUpdate{
				//de8ug with same procedure 
				if DEBUG{fmt.Printf("DE8UG: RATCHET ON EARLY MSG\n")}
				session.UpdateCounter++
				newroot = newroot.DeriveKey(ROOT_LABEL)
				newDHRKey := message.NextDHRatchet
				newDHRSecret := DHCombine(newDHRKey,&session.MyDHRatchet.PrivateKey)
				session.PartnerDHRatchet = newDHRKey.Duplicate()
				newroot = CombineKeys(newroot,newDHRSecret)
				newRecChain = newroot.DeriveKey(CHAIN_LABEL)
				newroot = newroot.DeriveKey(ROOT_LABEL)
			}
			saveKey := newRecChain.DeriveKey(KEY_LABEL)
			session.CachedReceiveKeys[session.ReceiveCounter] = saveKey.Duplicate()
			newRecChain = newRecChain.DeriveKey(CHAIN_LABEL)
			if DEBUG{fmt.Printf("saved key %x at position %d\n",session.CachedReceiveKeys[session.ReceiveCounter].String()[100:],session.ReceiveCounter)}
			
			//fmt.Printf("DE8UG: keys generated up to %d\n",session.ReceiveCounter)
		}

		session.ReceiveCounter++
		if session.ReceiveCounter == message.LastUpdate{
			//de8ug with same procedure 
			if DEBUG{fmt.Printf("DE8UG: RATCHET ON EARLY MSG\n")}
			session.UpdateCounter++
			newroot = newroot.DeriveKey(ROOT_LABEL)
			newDHRKey := message.NextDHRatchet
			newDHRSecret := DHCombine(newDHRKey,&session.MyDHRatchet.PrivateKey)
			session.PartnerDHRatchet = newDHRKey.Duplicate()
			newroot = CombineKeys(newroot,newDHRSecret)
			newRecChain = newroot.DeriveKey(CHAIN_LABEL)
			newroot = newroot.DeriveKey(ROOT_LABEL)
			}
		messageKey := newRecChain.DeriveKey(KEY_LABEL)
		// upd8 receive chain
		newRecChain = newRecChain.DeriveKey(CHAIN_LABEL)
		// fmt.Printf("DEBUG Receive: Derived message key: %x\n", messageKey.Key[:8])
		if DEBUG{
			//fmt.Printf("RECIEVE: %x\n         %x\n",messageKey.String()[100:],session.RootChain.String()[100:])
			fmt.Printf("DE8UG: Attempting decode with key %x on early message %d\n",messageKey.String()[100:],message.Counter)
		}// decrypt
		additionalData := message.EncodeAdditionalData()
		plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)
		if err != nil {
			newroot.Zeroize()
			newRecChain.Zeroize()
			return "", fmt.Errorf("authentication failed for eARLY message: %v", err)
		}
		if DEBUG{fmt.Println("decoded")}
		session.RootChain = newroot.Duplicate()
		session.ReceiveChain = newRecChain.Duplicate()
		newroot.Zeroize()
		newRecChain.Zeroize()
		return plaintext, nil
	} else if message.Counter-1 < session.ReceiveCounter{	
		if DEBUG{
			fmt.Printf("DE8UG: %d  recieving late message %d\n",session.IdentityFlag,message.Counter)	
			//fmt.Printf("retrieving key       %x at position %d\nexpected fingerprint %x\n",session.CachedReceiveKeys[message.Counter].String()[100:],message.Counter,message.DEBUGKey.String()[100:])
			}
		additionalData := message.EncodeAdditionalData()	
		decodeKey := session.CachedReceiveKeys[message.Counter]
		if decodeKey == nil{
			newroot.Zeroize()
			newRecChain.Zeroize()
			return "", fmt.Errorf("Duplicate or Invalid Message Counter %d in epoch %d",message.Counter,message.LastUpdate)
		}
		plaintext, err := decodeKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)
		session.CachedReceiveKeys[message.Counter].Zeroize()
		decodeKey.Zeroize()
		if err != nil {
			newroot.Zeroize()
			newRecChain.Zeroize()
			return "", fmt.Errorf("authentication failed for late message: %v", err)
		}
		if DEBUG{fmt.Println("decoded")}
		session.RootChain = newroot.Duplicate()
		session.ReceiveChain = newRecChain.Duplicate()
		newroot.Zeroize()
		newRecChain.Zeroize()
		return plaintext, nil
	} else if (message.Counter-1 == session.ReceiveCounter){
    	messageKey := newRecChain.DeriveKey(KEY_LABEL)
    	if DEBUG{fmt.Printf("DE8UG: %d recieving on-time message\n",session.IdentityFlag)}
		// upd8 receive chain
		newRecChain = newRecChain.DeriveKey(CHAIN_LABEL)
		
		session.ReceiveCounter++

		// fmt.Printf("DEBUG Receive: Derived message key: %x\n", messageKey.Key[:8])
		if DEBUG{
		//	fmt.Printf("RECIEVE: %x\n         %x\n",messageKey.String()[100:],session.RootChain.String()[100:])
			fmt.Printf("DE8UG: %d attempting decode with key %x on timed message %d\n",session.IdentityFlag,messageKey.String()[100:],message.Counter)	
		}// decrypt
		additionalData := message.EncodeAdditionalData()
		plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)
		if err != nil {
			//session.RootChain = startingRootKey.Duplicate()
			//session.ReceiveChain = startingChain.Duplicate()
			newroot.Zeroize()
			newRecChain.Zeroize()
			return "", fmt.Errorf("authentication failed for on time message: %v", err)
		}

		if DEBUG{fmt.Println("decoded")}
		session.RootChain = newroot.Duplicate()
		session.ReceiveChain = newRecChain.Duplicate()
		newroot.Zeroize()
		newRecChain.Zeroize()
		return plaintext, nil
	}
	return "", errors.New("FAILURE TO DECODE. UNMANAGED EDGE C8SE")
}
