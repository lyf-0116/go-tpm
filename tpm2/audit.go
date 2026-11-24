package tpm2

// AuditDigestVersion identifies the preimage layout used by CommandAudit.
// Version 2 uses the shared cpHash/rpHash preimage builder for both halves.
// Audit logs produced with an older version must be recomputed before their
// digests are compared with a TPM.
const AuditDigestVersion = 2

// CommandAudit represents an audit session for attesting the execution of a
// series of commands in the TPM. It is useful for both command and session
// auditing.
type CommandAudit struct {
	hash   TPMIAlgHash
	digest []byte
}

// NewAudit initializes a new CommandAudit with the specified hash algorithm.
func NewAudit(hash TPMIAlgHash) (*CommandAudit, error) {
	h, err := hash.Hash()
	if err != nil {
		return nil, err
	}
	return &CommandAudit{
		hash:   hash,
		digest: make([]byte, h.Size()),
	}, nil
}

// AuditCommand extends the audit digest with the given command and response.
// Go Generics do not allow type parameters on methods, otherwise this would be
// a method on CommandAudit.
// See https://github.com/golang/go/issues/49085 for more information.
func AuditCommand[C Command[R, *R], R any](a *CommandAudit, cmd C, rsp *R) error {
	cpHash, rpHash, err := auditHashes[R](a.hash, cmd, rsp)
	if err != nil {
		return err
	}
	ha, err := a.hash.Hash()
	if err != nil {
		return err
	}
	h := ha.New()
	h.Write(a.digest)
	h.Write(cpHash)
	h.Write(rpHash)
	a.digest = h.Sum(nil)
	return nil
}

// Digest returns the current digest of the audit.
func (a *CommandAudit) Digest() []byte {
	return a.digest
}

// Version returns the preimage layout version used by this audit digest.
func (a *CommandAudit) Version() int {
	return AuditDigestVersion
}

// auditHashes calculates the command and response parameter hashes from the
// same command code and the same preimage builder. The command is assumed to
// be successful and to not have any encrypt or decrypt sessions.
func auditHashes[R any](h TPMIAlgHash, c Command[R, *R], r *R) ([]byte, []byte, error) {
	cc := c.Command()
	cpPreimage, err := marshalCommandPreimage(cc, c)
	if err != nil {
		return nil, nil, err
	}
	rpPreimage, err := marshalResponsePreimage(cc, r)
	if err != nil {
		return nil, nil, err
	}
	cpHash, err := hashPreimage(h, cpPreimage)
	if err != nil {
		return nil, nil, err
	}
	rpHash, err := hashPreimage(h, rpPreimage)
	if err != nil {
		return nil, nil, err
	}
	return cpHash, rpHash, nil
}
