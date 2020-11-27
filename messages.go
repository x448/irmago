package irma

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/fxamacker/cbor"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

// Status encodes the status of an IRMA session (e.g., connected).
type Status string

const (
	MinVersionHeader = "X-IRMA-MinProtocolVersion"
	MaxVersionHeader = "X-IRMA-MaxProtocolVersion"
)

// ProtocolVersion encodes the IRMA protocol version of an IRMA session.
type ProtocolVersion struct {
	Major int
	Minor int
}

func NewVersion(major, minor int) *ProtocolVersion {
	return &ProtocolVersion{major, minor}
}

func (v *ProtocolVersion) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

func (v *ProtocolVersion) UnmarshalJSON(b []byte) (err error) {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		str = string(b) // If b is not enclosed by quotes, try it directly
	}
	parts := strings.Split(str, ".")
	if len(parts) != 2 {
		return errors.New("Invalid protocol version number: not of form x.y")
	}
	if v.Major, err = strconv.Atoi(parts[0]); err != nil {
		return
	}
	v.Minor, err = strconv.Atoi(parts[1])
	return
}

func (v *ProtocolVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

// Returns true if v is below the given version.
func (v *ProtocolVersion) Below(major, minor int) bool {
	if v.Major < major {
		return true
	}
	return v.Major == major && v.Minor < minor
}

func (v *ProtocolVersion) BelowVersion(other *ProtocolVersion) bool {
	return v.Below(other.Major, other.Minor)
}

func (v *ProtocolVersion) Above(major, minor int) bool {
	if v.Major > major {
		return true
	}
	return v.Major == major && v.Minor > minor
}

func (v *ProtocolVersion) AboveVersion(other *ProtocolVersion) bool {
	return v.Above(other.Major, other.Minor)
}

// GetMetadataVersion maps a chosen protocol version to a metadata version that
// the server will use.
func GetMetadataVersion(v *ProtocolVersion) byte {
	if v.Below(2, 3) {
		return 0x02 // no support for optional attributes
	}
	return 0x03 // current version
}

// Action encodes the session type of an IRMA session (e.g., disclosing).
type Action string

// ErrorType are session errors.
type ErrorType string

// SessionError is a protocol error.
type SessionError struct {
	Err error
	ErrorType
	Info         string
	RemoteError  *RemoteError
	RemoteStatus int
}

// RemoteError is an error message returned by the API server on errors.
type RemoteError struct {
	Status      int    `json:"status,omitempty"`
	ErrorName   string `json:"error,omitempty"`
	Description string `json:"description,omitempty"`
	Message     string `json:"message,omitempty"`
	Stacktrace  string `json:"stacktrace,omitempty"`
}

type Validator interface {
	Validate() error
}

// UnmarshalValidate json.Unmarshal's data, and validates it using the
// Validate() method if dest implements the Validator interface.
func UnmarshalValidate(data []byte, dest interface{}) error {
	if err := json.Unmarshal(data, dest); err != nil {
		return err
	}
	if v, ok := dest.(Validator); ok {
		return v.Validate()
	}
	return nil
}

func UnmarshalValidateBinary(data []byte, dest interface{}) error {
	if err := UnmarshalBinary(data, dest); err != nil {
		return err
	}
	if v, ok := dest.(Validator); ok {
		return v.Validate()
	}
	return nil
}

func MarshalBinary(message interface{}) ([]byte, error) {
	return cbor.Marshal(message, cbor.EncOptions{})
}

func UnmarshalBinary(data []byte, dst interface{}) error {
	return cbor.Unmarshal(data, dst)
}

func (err *RemoteError) Error() string {
	var msg string
	if err.Message != "" {
		msg = fmt.Sprintf(" (%s)", err.Message)
	}
	return fmt.Sprintf("%s%s: %s", err.ErrorName, msg, err.Description)
}

// Qr contains the data of an IRMA session QR (as generated by irma_js),
// suitable for NewSession().
type Qr struct {
	// Server with which to perform the session
	URL string `json:"u"`
	// Session type (disclosing, signing, issuing)
	Type Action `json:"irmaqr"`
}

// Statuses
const (
	StatusConnected     = Status("connected")
	StatusCommunicating = Status("communicating")
	StatusManualStarted = Status("manualStarted")
)

// Actions
const (
	ActionDisclosing = Action("disclosing")
	ActionSigning    = Action("signing")
	ActionIssuing    = Action("issuing")
	ActionRedirect   = Action("redirect")
	ActionRevoking   = Action("revoking")
	ActionUnknown    = Action("unknown")
)

// Protocol errors
const (
	// Protocol version not supported
	ErrorProtocolVersionNotSupported = ErrorType("protocolVersionNotSupported")
	// Error in HTTP communication
	ErrorTransport = ErrorType("transport")
	// HTTPS required
	ErrorHTTPS = ErrorType("https")
	// Invalid client JWT in first IRMA message
	ErrorInvalidJWT = ErrorType("invalidJwt")
	// Unkown session type (not disclosing, signing, or issuing)
	ErrorUnknownAction = ErrorType("unknownAction")
	// Crypto error during calculation of our response (second IRMA message)
	ErrorCrypto = ErrorType("crypto")
	// Error involving revocation or nonrevocation proofs
	ErrorRevocation = ErrorType("revocation")
	// Server rejected our response (second IRMA message)
	ErrorRejected = ErrorType("rejected")
	// (De)serializing of a message failed
	ErrorSerialization = ErrorType("serialization")
	// Error in keyshare protocol
	ErrorKeyshare = ErrorType("keyshare")
	// The user is not enrolled at one of the keyshare servers needed for the request
	ErrorKeyshareUnenrolled = ErrorType("keyshareUnenrolled")
	// API server error
	ErrorApi = ErrorType("api")
	// Server returned unexpected or malformed response
	ErrorServerResponse = ErrorType("serverResponse")
	// Credential type not present in our Configuration
	ErrorUnknownIdentifier = ErrorType("unknownIdentifier")
	// Non-optional attribute not present in credential
	ErrorRequiredAttributeMissing = ErrorType("requiredAttributeMissing")
	// Error during downloading of credential type, issuer, or public keys
	ErrorConfigurationDownload = ErrorType("configurationDownload")
	// IRMA requests refers to unknown scheme manager
	ErrorUnknownSchemeManager = ErrorType("unknownSchemeManager")
	// A session is requested involving a scheme manager that has some problem
	ErrorInvalidSchemeManager = ErrorType("invalidSchemeManager")
	// Invalid session request
	ErrorInvalidRequest = ErrorType("invalidRequest")
	// Recovered panic
	ErrorPanic = ErrorType("panic")
	// Error involving random blind attributes
	ErrorRandomBlind = ErrorType("randomblind")
)

type Disclosure struct {
	Proofs  gabi.ProofList            `json:"proofs"`
	Indices DisclosedAttributeIndices `json:"indices"`
}

// DisclosedAttributeIndices contains, for each conjunction of an attribute disclosure request,
// a list of attribute indices, pointing to where the disclosed attributes for that conjunction
// can be found within a gabi.ProofList.
type DisclosedAttributeIndices [][]*DisclosedAttributeIndex

// DisclosedAttributeIndex points to a specific attribute in a gabi.ProofList.
type DisclosedAttributeIndex struct {
	CredentialIndex int                  `json:"cred"`
	AttributeIndex  int                  `json:"attr"`
	Identifier      CredentialIdentifier `json:"-"` // credential from which this attribute was disclosed
}

type IssueCommitmentMessage struct {
	*gabi.IssueCommitmentMessage
	Indices DisclosedAttributeIndices `json:"indices,omitempty"`
}

//
// Keyshare messages
//

type KeyshareEnrollment struct {
	Pin      string  `json:"pin"`
	Email    *string `json:"email"`
	Language string  `json:"language"`
}

type KeyshareChangePin struct {
	Username string `json:"id"`
	OldPin   string `json:"oldpin"`
	NewPin   string `json:"newpin"`
}

type KeyshareAuthorization struct {
	Status     string   `json:"status"`
	Candidates []string `json:"candidates"`
}

type KeysharePinMessage struct {
	Username string `json:"id"`
	Pin      string `json:"pin"`
}

type KeysharePinStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type KeyshareCommitmentRequest struct {
	Keys  []PublicKeyIdentifier `json:"keys"`
	UserK *big.Int              `json:"userK"`
}

type ProofPCommitmentMap struct {
	Commitments map[PublicKeyIdentifier]*gabi.ProofPCommitment `json:"c"`
}

func (ppcm *ProofPCommitmentMap) MarshalJSON() ([]byte, error) {
	var encPPCM struct {
		Commitments map[string]*gabi.ProofPCommitment `json:"c"`
	}
	encPPCM.Commitments = make(map[string]*gabi.ProofPCommitment)

	for pki, v := range ppcm.Commitments {
		pkiBytes, err := pki.MarshalText()
		if err != nil {
			return nil, err
		}
		encPPCM.Commitments[string(pkiBytes)] = v
	}

	return json.Marshal(encPPCM)
}

//
// Errors
//

func (err ErrorType) Error() string {
	return string(err)
}

func (e *SessionError) Error() string {
	var buffer bytes.Buffer
	typ := e.ErrorType
	if typ == "" {
		typ = ErrorType("unknown")
	}

	buffer.WriteString("Error type: ")
	buffer.WriteString(string(typ))
	if e.Err != nil {
		buffer.WriteString("\nDescription: ")
		buffer.WriteString(e.Err.Error())
	}
	if e.RemoteStatus != 200 {
		buffer.WriteString("\nStatus code: ")
		buffer.WriteString(strconv.Itoa(e.RemoteStatus))
	}
	if e.RemoteError != nil {
		buffer.WriteString("\nIRMA server error: ")
		buffer.WriteString(e.RemoteError.Error())
	}

	return buffer.String()
}

func (e *SessionError) WrappedError() string {
	if e.Err == nil {
		return ""
	}

	return e.Err.Error()
}

func (e *SessionError) Stack() string {
	if withStack, ok := e.Err.(*errors.Error); ok {
		return string(withStack.Stack())
	}

	return ""
}

func (i *IssueCommitmentMessage) Disclosure() *Disclosure {
	return &Disclosure{
		Proofs:  i.Proofs,
		Indices: i.Indices,
	}
}

// ParseRequestorJwt parses the specified JWT and returns the contents.
// Note: this function does not verify the signature! Do that elsewhere.
func ParseRequestorJwt(action string, requestorJwt string) (RequestorJwt, error) {
	var retval RequestorJwt
	switch action {
	case "verification_request", string(ActionDisclosing):
		retval = &ServiceProviderJwt{}
	case "signature_request", string(ActionSigning):
		retval = &SignatureRequestorJwt{}
	case "issue_request", string(ActionIssuing):
		retval = &IdentityProviderJwt{}
	default:
		return nil, errors.New("Invalid session type")
	}
	if _, _, err := new(jwt.Parser).ParseUnverified(requestorJwt, retval); err != nil {
		return nil, err
	}
	if err := retval.RequestorRequest().Validate(); err != nil {
		return nil, errors.WrapPrefix(err, "Invalid JWT body", 0)
	}
	return retval, nil
}

func (qr *Qr) IsQr() bool {
	switch qr.Type {
	case ActionDisclosing: // nop
	case ActionIssuing: // nop
	case ActionSigning: // nop
	case ActionRedirect: // nop
	default:
		return false
	}
	return true
}

func (qr *Qr) Validate() (err error) {
	if qr.URL == "" {
		return errors.New("no URL specified")
	}
	if _, err = url.ParseRequestURI(qr.URL); err != nil {
		return errors.Errorf("invalid URL: %s", err.Error())
	}
	if !qr.IsQr() {
		return errors.New("unsupported session type")
	}
	return nil
}
