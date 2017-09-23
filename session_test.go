/// +build integration

package irmago

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type TestHandler struct {
	t *testing.T
	c chan *Error
}

func (th TestHandler) StatusUpdate(action Action, status Status) {}
func (th TestHandler) Success(action Action) {
	th.c <- nil
}
func (th TestHandler) Cancelled(action Action) {
	th.c <- &Error{}
}
func (th TestHandler) Failure(action Action, err *Error) {
	th.c <- err
}
func (th TestHandler) UnsatisfiableRequest(action Action, missing AttributeDisjunctionList) {
	th.c <- &Error{}
}
func (th TestHandler) AskVerificationPermission(request DisclosureRequest, ServerName string, callback PermissionHandler) {
	choice := &DisclosureChoice{
		Attributes: []*AttributeIdentifier{},
	}
	var candidates []*AttributeIdentifier
	for _, disjunction := range request.Content {
		candidates = Manager.Candidates(disjunction)
		require.NotNil(th.t, candidates)
		require.NotEmpty(th.t, candidates, 1)
		choice.Attributes = append(choice.Attributes, candidates[0])
	}
	callback(true, choice)
}
func (th TestHandler) AskIssuancePermission(request IssuanceRequest, ServerName string, callback PermissionHandler) {
	dreq := DisclosureRequest{
		SessionRequest: request.SessionRequest,
		Content:        request.Disclose,
	}
	th.AskVerificationPermission(dreq, ServerName, callback)
}
func (th TestHandler) AskSignaturePermission(request SignatureRequest, ServerName string, callback PermissionHandler) {
	th.AskVerificationPermission(request.DisclosureRequest, ServerName, callback)
}
func (th TestHandler) AskPin(remainingAttempts int, callback func(proceed bool, pin string)) {
	callback(true, "12345")
}

func getDisclosureJwt(name string, id AttributeTypeIdentifier) interface{} {
	return NewServiceProviderJwt(name, &DisclosureRequest{
		Content: AttributeDisjunctionList([]*AttributeDisjunction{{
			Label:      "foo",
			Attributes: []AttributeTypeIdentifier{id},
		}}),
	})
}

func getSigningJwt(name string, id AttributeTypeIdentifier) interface{} {
	return NewSignatureRequestorJwt(name, &SignatureRequest{
		Message:     "test",
		MessageType: "STRING",
		DisclosureRequest: DisclosureRequest{
			Content: AttributeDisjunctionList([]*AttributeDisjunction{{
				Label:      "foo",
				Attributes: []AttributeTypeIdentifier{id},
			}}),
		},
	})
}

func getIssuanceJwt(name string, id AttributeTypeIdentifier) interface{} {
	expiry := Timestamp(NewMetadataAttribute().Expiry())
	credid1 := NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	credid2 := NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
	return NewIdentityProviderJwt(name, &IssuanceRequest{
		Credentials: []*CredentialRequest{
			{
				Validity:   &expiry,
				Credential: &credid1,
				Attributes: map[string]string{
					"university":        "Radboud",
					"studentCardNumber": "3.1415926535897932384626433832795028841971694",
					"studentID":         "s1234567",
					"level":             "42",
				},
			}, {
				Validity:   &expiry,
				Credential: &credid2,
				Attributes: map[string]string{
					"BSN": "299792458",
				},
			},
		},
		Disclose: AttributeDisjunctionList{
			&AttributeDisjunction{Label: "foo", Attributes: []AttributeTypeIdentifier{id}},
		},
	})
}

// StartSession starts an IRMA session by posting the request,
// and retrieving the QR contents from the specified url.
func StartSession(request interface{}, url string) (*Qr, error) {
	server := NewHTTPTransport(url)
	var response Qr
	err := server.Post("", &response, request)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func TestSigningSession(t *testing.T) {
	id := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsigclient"

	jwtcontents := getSigningJwt(name, id)
	sessionHelper(t, jwtcontents, "signature", true)
}

func TestDisclosureSession(t *testing.T) {
	id := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsp"

	jwtcontents := getDisclosureJwt(name, id)
	sessionHelper(t, jwtcontents, "verification", true)
}

func TestIssuanceSession(t *testing.T) {
	id := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testip"

	jwtcontents := getIssuanceJwt(name, id)
	sessionHelper(t, jwtcontents, "issue", true)
}

func sessionHelper(t *testing.T, jwtcontents interface{}, url string, init bool) {
	if init {
		parseMetaStore(t)
		parseStorage(t)
		parseAndroidStorage(t)
	}

	url = "http://localhost:8081/irma_api_server/api/v2/" + url
	//url = "https://demo.irmacard.org/tomcat/irma_api_server/api/v2/" + url

	headerbytes, err := json.Marshal(&map[string]string{"alg": "none", "typ": "JWT"})
	require.NoError(t, err)
	bodybytes, err := json.Marshal(jwtcontents)
	require.NoError(t, err)

	jwt := base64.RawStdEncoding.EncodeToString(headerbytes) + "." + base64.RawStdEncoding.EncodeToString(bodybytes) + "."
	qr, transportErr := StartSession(jwt, url)
	if transportErr != nil {
		fmt.Printf("+%v\n", transportErr)
	}
	require.NoError(t, transportErr)
	qr.URL = url + "/" + qr.URL

	c := make(chan *Error)
	NewSession(qr, TestHandler{t, c})

	if err := <-c; err != nil {
		t.Fatal(*err)
	}

	teardown(t)
}

func registerKeyshareServer(t *testing.T) {
	parseMetaStore(t)
	parseStorage(t)
	parseAndroidStorage(t)

	test := NewSchemeManagerIdentifier("test")
	err := Manager.KeyshareRemove(test)
	require.NoError(t, err)

	bytes := make([]byte, 8, 8)
	rand.Read(bytes)
	email := fmt.Sprintf("%s@example.com", hex.EncodeToString(bytes))
	err = Manager.KeyshareEnroll(test, email, "12345")
	require.NoError(t, err)
}

func TestKeyshareSession(t *testing.T) {
	registerKeyshareServer(t)

	expiry := Timestamp(NewMetadataAttribute().Expiry())
	credid := NewCredentialTypeIdentifier("test.test.mijnirma")
	jwtcontents := NewIdentityProviderJwt("testip", &IssuanceRequest{
		Credentials: []*CredentialRequest{
			{
				Validity:   &expiry,
				Credential: &credid,
				Attributes: map[string]string{"email": "example@example.com"},
			},
		},
	})

	sessionHelper(t, jwtcontents, "issue", false)
}
