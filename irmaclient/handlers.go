package irmaclient

import (
	"reflect"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
)

// keyshareEnrollmentHandler handles the keyshare attribute issuance session
// after registering to a new keyshare server.
type (
	keyshareEnrollmentHandler struct {
		pin    string
		client *Client
		kss    *keyshareServer
	}

	refreshHandler struct {
		Handler
		client        *Client
		dismisser     SessionDismisser
		credhash      string
		disclosed     bool
		disclosureURL string
		choice        *irma.DisclosureChoice
	}
)

// Force keyshareEnrollmentHandler to implement the Handler interface
var _ Handler = (*keyshareEnrollmentHandler)(nil)

// Session handlers in the order they are called

func (h *keyshareEnrollmentHandler) RequestIssuancePermission(request *irma.IssuanceRequest, candidates [][][]*irma.AttributeIdentifier, ServerName irma.TranslatedString, callback PermissionHandler) {
	// Fetch the username from the credential request and save it along with the scheme manager
	for _, attr := range request.Credentials[0].Attributes {
		h.kss.Username = attr
		break
	}

	// Do the issuance
	callback(true, nil)
}

func (h *keyshareEnrollmentHandler) RequestPin(remainingAttempts int, callback PinHandler) {
	if remainingAttempts == -1 { // -1 signifies that this is the first attempt
		callback(true, h.pin)
	} else {
		h.fail(errors.New("PIN incorrect"))
	}
}

func (h *keyshareEnrollmentHandler) Success(result string) {
	_ = h.client.storage.StoreKeyshareServers(h.client.keyshareServers) // TODO handle err?
	h.client.handler.EnrollmentSuccess(h.kss.SchemeManagerIdentifier)
}

func (h *keyshareEnrollmentHandler) Failure(err *irma.SessionError) {
	h.fail(err)
}

// fail is a helper to ensure the kss is removed from the client in case of any problem
func (h *keyshareEnrollmentHandler) fail(err error) {
	delete(h.client.keyshareServers, h.kss.SchemeManagerIdentifier)
	h.client.handler.EnrollmentFailure(h.kss.SchemeManagerIdentifier, err)
}

// Not interested, ingore
func (h *keyshareEnrollmentHandler) StatusUpdate(action irma.Action, status irma.Status) {}

// The methods below should never be called, so we let each of them fail the session
func (h *keyshareEnrollmentHandler) RequestVerificationPermission(request *irma.DisclosureRequest, candidates [][][]*irma.AttributeIdentifier, ServerName irma.TranslatedString, callback PermissionHandler) {
	callback(false, nil)
}
func (h *keyshareEnrollmentHandler) RequestSignaturePermission(request *irma.SignatureRequest, candidates [][][]*irma.AttributeIdentifier, ServerName irma.TranslatedString, callback PermissionHandler) {
	callback(false, nil)
}
func (h *keyshareEnrollmentHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	callback(false)
}
func (h *keyshareEnrollmentHandler) Cancelled() {
	h.fail(errors.New("Keyshare enrollment session unexpectedly cancelled"))
}
func (h *keyshareEnrollmentHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	h.fail(errors.New("Keyshare enrollment failed: blocked"))
}
func (h *keyshareEnrollmentHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	h.fail(errors.New("Keyshare enrollment failed: registration incomplete"))
}
func (h *keyshareEnrollmentHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	h.fail(errors.New("Keyshare enrollment failed: not enrolled"))
}
func (h *keyshareEnrollmentHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	h.fail(errors.New("Keyshare enrollment failed: unenrolled"))
}
func (h *keyshareEnrollmentHandler) UnsatisfiableRequest(request irma.SessionRequest, ServerName irma.TranslatedString, missing MissingAttributes) {
	h.fail(errors.New("Keyshare enrollment failed: unsatisfiable"))
}
func (h *keyshareEnrollmentHandler) ClientReturnURLSet(clientReturnURL string) {
	h.fail(errors.New("Keyshare enrollment session unexpectedly found an external return url"))
}

func (h *refreshHandler) RequestVerificationPermission(request *irma.DisclosureRequest, candidates [][][]*irma.AttributeIdentifier, ServerName irma.TranslatedString, callback PermissionHandler) {
	// verify that the disclosure request is exactly what it should be according to the scheme
	cred, _, _ := h.client.credentialByHash(h.credhash) // err != nil as this would have happened earlier
	expectedRequest, _ := cred.CredentialType().RefreshDisclosureRequest()
	if !reflect.DeepEqual(request.Disclose, expectedRequest.Disclose) {
		h.dismisser.Dismiss()
		h.Failure(&irma.SessionError{ErrorType: irma.ErrorServerResponse})
		return
	}

	// in case the user has other instances of the same type of our credential,
	// filter them away from the options
	var filtered [][][]*irma.AttributeIdentifier
	for _, attrlistlist := range candidates {
		var newlistlist [][]*irma.AttributeIdentifier
		for _, attrlist := range attrlistlist {
			var newlist []*irma.AttributeIdentifier
			for _, attr := range attrlist {
				if attr.CredentialHash == h.credhash {
					newlist = append(newlist, attr)
				}
			}
			newlistlist = append(newlistlist, newlist)
		}
		filtered = append(filtered, newlistlist)
	}

	// ask deferred handler for permission, storing the user's choice
	h.Handler.RequestVerificationPermission(request, filtered, ServerName, func(proceed bool, choice *irma.DisclosureChoice) {
		h.choice = choice
		callback(proceed, choice)
	})
}

func (h *refreshHandler) Success(_ string) {
	// At the end of the disclosure session, we start the issuance session;
	// at the end of the issuance session we are done.
	if h.disclosed {
		h.Handler.Success("")
		return
	}
	h.disclosed = true

	// Retrieve issuance session
	transport := irma.NewHTTPTransport(h.disclosureURL)
	var qr irma.Qr
	if err := transport.Post("next", &qr, nil); err != nil {
		h.Failure(&irma.SessionError{ErrorType: irma.ErrorServerResponse, Err: err})
		return
	}

	// Start issuance session reusing this handler
	h.dismisser = h.client.newQrSession(&qr, h)
}

func (h *refreshHandler) RequestIssuancePermission(_ *irma.IssuanceRequest, _ [][][]*irma.AttributeIdentifier, _ irma.TranslatedString, callback PermissionHandler) {
	// This will be a combined issuance/disclosure session in which the server requires us
	// to disclose exactly the same attributes as before. We just reuse the previously made
	// disclosure choice and accept.
	callback(true, h.choice)
}
