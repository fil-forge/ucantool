package ucandelegate_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantool/pkg/identity"
	"github.com/fil-forge/ucantool/pkg/ucandelegate"
	"github.com/stretchr/testify/require"
)

// newRequest builds a minimal valid request with a freshly generated signer.
func newRequest(t *testing.T) ucandelegate.Request {
	t.Helper()
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	return ucandelegate.Request{
		Signer:   signer,
		Audience: testutil.RandomDID(t).String(),
		Commands: []string{"/msg/send"},
	}
}

func TestDelegateSingleCommand(t *testing.T) {
	dlgs, err := ucandelegate.Delegate(newRequest(t))
	require.NoError(t, err)
	require.Len(t, dlgs, 1)
}

func TestDelegateOneDelegationPerCommand(t *testing.T) {
	req := newRequest(t)
	req.Commands = []string{"/msg/send", "/msg/recv"}

	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)

	commands := make([]string, 0, len(dlgs))
	for _, dlg := range dlgs {
		commands = append(commands, dlg.Command().String())
	}
	require.Equal(t, []string{"/msg/send", "/msg/recv"}, commands)
}

func TestDelegateAudience(t *testing.T) {
	req := newRequest(t)

	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)
	require.Equal(t, req.Audience, dlgs[0].Audience().String())
}

func TestDelegateSubjectDefaultsToIssuer(t *testing.T) {
	req := newRequest(t)

	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)
	require.Equal(t, req.Signer.KeyDID(), dlgs[0].Subject())
}

func TestDelegateExplicitSubject(t *testing.T) {
	req := newRequest(t)
	req.Subject = testutil.RandomDID(t).String()

	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)
	require.Equal(t, req.Subject, dlgs[0].Subject().String())
}

func TestDelegateIssuerDIDWeb(t *testing.T) {
	req := newRequest(t)
	req.IssuerDIDWeb = "did:web:example.com"

	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)
	require.Equal(t, req.IssuerDIDWeb, dlgs[0].Issuer().String())
}

func TestDelegateIssuerDefaultsToSignerKeyDID(t *testing.T) {
	req := newRequest(t)

	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)
	require.Equal(t, req.Signer.KeyDID(), dlgs[0].Issuer())
}

// A nil Expiration must produce a delegation that never expires. Passing no
// expiration option to ucantone would silently expire it 30 seconds from now.
func TestDelegateNilExpirationNeverExpires(t *testing.T) {
	dlgs, err := ucandelegate.Delegate(newRequest(t))
	require.NoError(t, err)
	require.Nil(t, dlgs[0].Expiration())
}

func TestDelegateExpiration(t *testing.T) {
	req := newRequest(t)
	exp := ucan.Now() + 3600
	req.Expiration = &exp

	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)
	require.Equal(t, &exp, dlgs[0].Expiration())
}

func TestDelegateExpiresIn(t *testing.T) {
	req := newRequest(t)
	req.Expiration = ucandelegate.ExpiresIn(time.Hour)

	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)
	require.Equal(t, req.Expiration, dlgs[0].Expiration())
}

func TestExpiresAtTruncatesToWholeSecond(t *testing.T) {
	at := time.Unix(1770000000, 999999999)
	require.Equal(t, ucan.UnixTimestamp(1770000000), *ucandelegate.ExpiresAt(at))
}

func TestExpiresInIsRelativeToNow(t *testing.T) {
	exp := *ucandelegate.ExpiresIn(time.Hour)
	require.InDelta(t, int64(ucan.Now()+3600), int64(exp), 2)
}

func TestDelegatePolicy(t *testing.T) {
	req := newRequest(t)
	req.Policy = `[["==", ".foo", "bar"]]`

	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)

	statements := dlgs[0].Policy().Statements()
	require.Len(t, statements, 1)
	require.Equal(t, policy.OpEqual, statements[0].Operator())
}

func TestDelegateInvalidRequests(t *testing.T) {
	invalidRequests := map[string]struct {
		mutate         func(req *ucandelegate.Request)
		expectedErrMsg string
	}{
		"signer is missing": {
			mutate:         func(req *ucandelegate.Request) { req.Signer = nil },
			expectedErrMsg: "signer is required",
		},
		"audience is empty": {
			mutate:         func(req *ucandelegate.Request) { req.Audience = "" },
			expectedErrMsg: "audience is required",
		},
		"commands are empty": {
			mutate:         func(req *ucandelegate.Request) { req.Commands = nil },
			expectedErrMsg: "at least one command is required",
		},
		"audience is not a DID": {
			mutate:         func(req *ucandelegate.Request) { req.Audience = "not-a-did" },
			expectedErrMsg: "parsing audience DID",
		},
		"subject is not a DID": {
			mutate:         func(req *ucandelegate.Request) { req.Subject = "not-a-did" },
			expectedErrMsg: "parsing subject DID",
		},
		"issuer DID is not a DID": {
			mutate:         func(req *ucandelegate.Request) { req.IssuerDIDWeb = "not-a-did" },
			expectedErrMsg: "parsing issuer DID",
		},
		"issuer DID is not did:web": {
			mutate:         func(req *ucandelegate.Request) { req.IssuerDIDWeb = "did:key:z6Mk" },
			expectedErrMsg: "expected web",
		},
		"issuer did:web has a malformed port": {
			mutate:         func(req *ucandelegate.Request) { req.IssuerDIDWeb = "did:web:example.com%3Ahttp" },
			expectedErrMsg: "not a port number",
		},
		"command has no leading slash": {
			mutate:         func(req *ucandelegate.Request) { req.Commands = []string{"msg/send"} },
			expectedErrMsg: "parsing command",
		},
		"policy is not valid DAG-JSON": {
			mutate:         func(req *ucandelegate.Request) { req.Policy = "{not json" },
			expectedErrMsg: "parsing policy",
		},
		"expiration is in the past": {
			mutate: func(req *ucandelegate.Request) {
				exp := ucan.Now() - 1
				req.Expiration = &exp
			},
			expectedErrMsg: "is in the past",
		},
	}

	for desc, tc := range invalidRequests {
		t.Run(desc, func(t *testing.T) {
			req := newRequest(t)
			tc.mutate(&req)
			_, err := ucandelegate.Delegate(req)
			require.ErrorContains(t, err, tc.expectedErrMsg)
		})
	}
}

func TestEncodeSingleDelegationAsBareCBOR(t *testing.T) {
	dlgs, err := ucandelegate.Delegate(newRequest(t))
	require.NoError(t, err)

	res, err := ucandelegate.Encode(dlgs, "")
	require.NoError(t, err)
	require.Equal(t, byte(0), res.Codec)

	decoded, err := delegation.Decode(res.Bytes)
	require.NoError(t, err)
	require.Equal(t, dlgs[0].Link(), decoded.Link())
}

func TestEncodeMultipleDelegationsAsDefaultContainer(t *testing.T) {
	req := newRequest(t)
	req.Commands = []string{"/msg/send", "/msg/recv"}
	dlgs, err := ucandelegate.Delegate(req)
	require.NoError(t, err)

	res, err := ucandelegate.Encode(dlgs, "")
	require.NoError(t, err)
	require.Equal(t, container.Base64Gzip, res.Codec)

	decoded, err := container.Decode(res.Bytes)
	require.NoError(t, err)
	require.Len(t, decoded.Delegations(), 2)
}

func TestEncodeSingleDelegationWithExplicitCodec(t *testing.T) {
	dlgs, err := ucandelegate.Delegate(newRequest(t))
	require.NoError(t, err)

	res, err := ucandelegate.Encode(dlgs, "raw")
	require.NoError(t, err)
	require.Equal(t, container.Raw, res.Codec)

	decoded, err := container.Decode(res.Bytes)
	require.NoError(t, err)
	require.Len(t, decoded.Delegations(), 1)
}

func TestEncodeUnknownCodec(t *testing.T) {
	dlgs, err := ucandelegate.Delegate(newRequest(t))
	require.NoError(t, err)

	_, err = ucandelegate.Encode(dlgs, "bogus")
	require.ErrorContains(t, err, "invalid container codec")
}

func TestEncodeNoDelegations(t *testing.T) {
	_, err := ucandelegate.Encode(nil, "")
	require.ErrorContains(t, err, "no delegations to encode")
}

func TestResultIsText(t *testing.T) {
	textual := map[byte]bool{
		0:                       false,
		container.Raw:           false,
		container.RawGzip:       false,
		container.Base64:        true,
		container.Base64Gzip:    true,
		container.Base64urlGzip: true,
	}
	for codec, expected := range textual {
		t.Run(container.FormatCodec(codec), func(t *testing.T) {
			require.Equal(t, expected, ucandelegate.Result{Codec: codec}.IsText())
		})
	}
}

func TestResultWriteToTerminatesTextWithNewline(t *testing.T) {
	res := ucandelegate.Result{Bytes: []byte("Fabc"), Codec: container.Base64Gzip}

	var out bytes.Buffer
	written, err := res.WriteTo(&out)
	require.NoError(t, err)
	require.Equal(t, "Fabc\n", out.String())
	require.Equal(t, int64(out.Len()), written)
}

func TestResultWriteToWritesBinaryBare(t *testing.T) {
	res := ucandelegate.Result{Bytes: []byte{0x40, 0x01}, Codec: container.Raw}

	var out bytes.Buffer
	written, err := res.WriteTo(&out)
	require.NoError(t, err)
	require.Equal(t, []byte{0x40, 0x01}, out.Bytes())
	require.Equal(t, int64(2), written)
}

func TestResultWriteToWritesBareDelegationBare(t *testing.T) {
	dlgs, err := ucandelegate.Delegate(newRequest(t))
	require.NoError(t, err)
	res, err := ucandelegate.Encode(dlgs, "")
	require.NoError(t, err)

	var out bytes.Buffer
	_, err = res.WriteTo(&out)
	require.NoError(t, err)

	// Decoding fails if a newline trails the delegation.
	_, err = delegation.Decode(out.Bytes())
	require.NoError(t, err)
}

func TestIssueUsesRequestCodec(t *testing.T) {
	req := newRequest(t)
	req.ContainerCodec = "base64url+gzip"

	res, err := ucandelegate.Issue(req)
	require.NoError(t, err)
	require.Equal(t, container.Base64urlGzip, res.Codec)

	decoded, err := container.Decode(res.Bytes)
	require.NoError(t, err)
	require.Len(t, decoded.Delegations(), 1)
}

func TestIssueFromPEM(t *testing.T) {
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	pemData, err := identity.EncodeSignerToPEM(signer)
	require.NoError(t, err)

	res, err := ucandelegate.IssueFromPEM(pemData, ucandelegate.Request{
		Audience: testutil.RandomDID(t).String(),
		Commands: []string{"/msg/send"},
	})
	require.NoError(t, err)
	require.Equal(t, byte(0), res.Codec)

	decoded, err := delegation.Decode(res.Bytes)
	require.NoError(t, err)
	require.Equal(t, signer.KeyDID(), decoded.Issuer())
}

func TestIssueFromPEMRejectsSigner(t *testing.T) {
	req := newRequest(t)
	_, err := ucandelegate.IssueFromPEM(nil, req)
	require.ErrorContains(t, err, "signer must not be set")
}

func TestIssueFromPEMInvalidPEM(t *testing.T) {
	_, err := ucandelegate.IssueFromPEM([]byte("not a pem"), ucandelegate.Request{
		Audience: testutil.RandomDID(t).String(),
		Commands: []string{"/msg/send"},
	})
	require.ErrorContains(t, err, "decoding issuer private key")
}
