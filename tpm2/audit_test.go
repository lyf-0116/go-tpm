package tpm2

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestAuditCommandUsesSharedPreimages(t *testing.T) {
	name := TPM2BName{Buffer: bytes.Repeat([]byte{0x42}, sha256.Size+2)}
	cmd := Hmac{
		Handle: AuthHandle{
			Handle: 0x80000000,
			Name:   name,
		},
		Buffer:  TPM2BMaxBuffer{Buffer: []byte("audit me")},
		HashAlg: TPMAlgSHA256,
	}
	rsp := HmacResponse{
		OutHMAC: TPM2BDigest{Buffer: bytes.Repeat([]byte{0x24}, sha256.Size)},
	}

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	if err := AuditCommand(audit, cmd, &rsp); err != nil {
		t.Fatalf("AuditCommand: %v", err)
	}

	cpPreimage, err := MarshalCommand(cmd)
	if err != nil {
		t.Fatalf("MarshalCommand: %v", err)
	}
	rpPreimage, err := MarshalResponse(cmd, &rsp)
	if err != nil {
		t.Fatalf("MarshalResponse: %v", err)
	}
	cpHash := sha256.Sum256(cpPreimage)
	rpHash := sha256.Sum256(rpPreimage)

	h := sha256.New()
	h.Write(make([]byte, sha256.Size))
	h.Write(cpHash[:])
	h.Write(rpHash[:])
	want := h.Sum(nil)

	if got := audit.Digest(); !bytes.Equal(got, want) {
		t.Fatalf("audit digest = %x, want %x", got, want)
	}
	if got := audit.Version(); got != AuditDigestVersion {
		t.Fatalf("audit version = %d, want %d", got, AuditDigestVersion)
	}
}

func TestUnmarshalCommandPopulatesConcreteHandles(t *testing.T) {
	objName := TPM2BName{Buffer: append([]byte{0x00, 0x0b}, bytes.Repeat([]byte{0x11}, sha256.Size)...)}
	cmd := GetTime{
		PrivacyAdminHandle: TPMRHEndorsement,
		SignHandle: NamedHandle{
			Handle: 0x80000000,
			Name:   objName,
		},
		QualifyingData: TPM2BData{Buffer: []byte("nonce")},
		InScheme: TPMTSigScheme{
			Scheme: TPMAlgECDSA,
			Details: NewTPMUSigScheme(
				TPMAlgECDSA,
				&TPMSSchemeHash{HashAlg: TPMAlgSHA256},
			),
		},
	}

	want, err := MarshalCommand(cmd)
	if err != nil {
		t.Fatalf("MarshalCommand: %v", err)
	}
	gotCmd, err := UnmarshalCommand[GetTime](want)
	if err != nil {
		t.Fatalf("UnmarshalCommand: %v", err)
	}
	got, err := MarshalCommand(gotCmd)
	if err != nil {
		t.Fatalf("MarshalCommand after replay: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("replayed command preimage = %x, want %x", got, want)
	}
	if gotCmd.PrivacyAdminHandle != TPMRHEndorsement {
		t.Fatalf("privacy admin handle = %#x, want %#x", gotCmd.PrivacyAdminHandle, TPMRHEndorsement)
	}
}
