// Package ucandelegate issues UCAN delegations signed by an in-memory key.
package ucandelegate

import (
	"fmt"
	"io"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/web"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantool/pkg/identity"
	"github.com/fil-forge/ucantool/pkg/ucanfmt"
)

// Request describes the delegations to issue.
type Request struct {
	// Signer signs the delegations. Required.
	Signer multikey.Signer

	// IssuerDIDWeb wraps the signer's did:key in a did:web issuer DID. When
	// set, it must be a did:web DID. Optional.
	IssuerDIDWeb string

	// Audience is the DID the delegations are issued to. Required.
	Audience string

	// Subject is the DID the delegations are about. Defaults to the issuer DID.
	Subject string

	// Commands are the commands the issuer authorizes the audience to invoke,
	// one delegation per command. At least one is required.
	Commands []string

	// Policy is a policy encoded as a DAG-JSON string. Optional.
	Policy string

	// Expiration is the time the delegations expire, in seconds since the Unix
	// epoch.
	//
	// WARNING: a nil Expiration issues delegations that are valid FOREVER,
	// unless revoked.
	Expiration *ucan.UnixTimestamp

	// ContainerCodec names the UCAN container codec to encode the delegations
	// with. An empty ContainerCodec encodes a single delegation as a bare
	// DAG-CBOR block, and multiple delegations with
	// [ucanfmt.DefaultContainerCodec].
	ContainerCodec string
}

// ExpiresAt returns t as a delegation expiration time, truncated to a whole
// second.
func ExpiresAt(t time.Time) *ucan.UnixTimestamp {
	exp := ucan.UnixTimestamp(t.Unix())
	return &exp
}

// ExpiresIn returns a delegation expiration time d from now, truncated to a
// whole second.
func ExpiresIn(d time.Duration) *ucan.UnixTimestamp {
	return ExpiresAt(time.Now().Add(d))
}

// Result holds encoded delegations.
type Result struct {
	// Bytes are the encoded delegations.
	Bytes []byte

	// Codec is the UCAN container codec Bytes are encoded with, or 0 when Bytes
	// are a bare DAG-CBOR delegation.
	Codec byte
}

// IsText reports whether Bytes are printable text rather than binary.
func (r Result) IsText() bool {
	return ucanfmt.IsTextualCodec(r.Codec)
}

// WriteTo writes the encoded delegations to w, terminating printable text with
// a newline and writing binary output bare.
func (r Result) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(r.Bytes)
	if err != nil || !r.IsText() {
		return int64(n), err
	}
	nl, err := w.Write([]byte{'\n'})
	return int64(n + nl), err
}

// IssueFromPEM issues the delegations described by req, signed with the private
// key held in a PKCS#8 PEM. req.Signer must not be set.
func IssueFromPEM(pemData []byte, req Request) (Result, error) {
	if req.Signer != nil {
		return Result{}, fmt.Errorf("signer must not be set when issuing from a PEM")
	}

	signer, err := identity.DecodeSignerFromPEM(pemData)
	if err != nil {
		return Result{}, fmt.Errorf("decoding issuer private key: %w", err)
	}

	req.Signer = signer
	return Issue(req)
}

// Issue creates the delegations described by req and encodes them.
func Issue(req Request) (Result, error) {
	dlgs, err := Delegate(req)
	if err != nil {
		return Result{}, err
	}
	return Encode(dlgs, req.ContainerCodec)
}

// Delegate creates one delegation per command in req.
func Delegate(req Request) ([]ucan.Delegation, error) {
	if req.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	if req.Audience == "" {
		return nil, fmt.Errorf("audience is required")
	}
	if len(req.Commands) == 0 {
		return nil, fmt.Errorf("at least one command is required")
	}

	issuer, err := newIssuer(req)
	if err != nil {
		return nil, err
	}

	audience, err := did.Parse(req.Audience)
	if err != nil {
		return nil, fmt.Errorf("parsing audience DID: %w", err)
	}

	var opts []delegation.Option
	if req.Expiration != nil {
		if ucan.Now() > *req.Expiration {
			return nil, fmt.Errorf("provided expiration time %d is in the past", *req.Expiration)
		}
		opts = append(opts, delegation.WithExpiration(*req.Expiration))
	} else {
		// Passing no expiration option at all would make the delegation expire
		// 30 seconds from now.
		opts = append(opts, delegation.WithNoExpiration())
	}

	subject := issuer.DID()
	if req.Subject != "" {
		subject, err = did.Parse(req.Subject)
		if err != nil {
			return nil, fmt.Errorf("parsing subject DID: %w", err)
		}
	}

	var commands []ucan.Command
	for _, commandStr := range req.Commands {
		cmd, err := command.Parse(commandStr)
		if err != nil {
			return nil, fmt.Errorf("parsing command: %w", err)
		}
		commands = append(commands, cmd)
	}

	if req.Policy != "" {
		pol, err := policy.Parse(req.Policy)
		if err != nil {
			return nil, fmt.Errorf("parsing policy: %w", err)
		}
		opts = append(opts, delegation.WithPolicy(pol))
	}

	var delegations []ucan.Delegation
	for _, cmd := range commands {
		dlg, err := delegation.Delegate(issuer, audience, subject, cmd, opts...)
		if err != nil {
			return nil, fmt.Errorf("creating delegation: %w", err)
		}
		delegations = append(delegations, dlg)
	}

	return delegations, nil
}

// Encode encodes delegations in a UCAN container with the named codec. An empty
// codec encodes a single delegation as a bare DAG-CBOR block and multiple
// delegations with [ucanfmt.DefaultContainerCodec].
func Encode(dlgs []ucan.Delegation, codec string) (Result, error) {
	if len(dlgs) == 0 {
		return Result{}, fmt.Errorf("no delegations to encode")
	}

	if len(dlgs) == 1 && codec == "" {
		out, err := delegation.Encode(dlgs[0])
		if err != nil {
			return Result{}, fmt.Errorf("formatting delegation: %w", err)
		}
		return Result{Bytes: out}, nil
	}

	if codec == "" {
		codec = ucanfmt.DefaultContainerCodec
	}
	containerCodec, err := ucanfmt.ParseCodec(codec)
	if err != nil {
		return Result{}, err
	}

	out, err := container.Encode(containerCodec, container.New(container.WithDelegations(dlgs...)))
	if err != nil {
		return Result{}, fmt.Errorf("encoding container: %w", err)
	}

	return Result{Bytes: out, Codec: containerCodec}, nil
}

// newIssuer builds the delegation issuer, wrapping the signer's did:key in a
// did:web DID when req asks for one.
func newIssuer(req Request) (multikey.Issuer, error) {
	if req.IssuerDIDWeb == "" {
		return multikey.KeyIssuer(req.Signer), nil
	}

	issuerDID, err := web.Parse(req.IssuerDIDWeb)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer DID: %w", err)
	}

	return multikey.NewIssuer(issuerDID, req.Signer), nil
}
