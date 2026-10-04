//go:build windows

package secret

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Protector struct{}

// New selects machine-scope DPAPI so a service can read CLI-created secrets.
// The protected directory ACL grants only SYSTEM and Administrators full access.
func New(dataDir string) (*Protector, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create DPAPI data directory: %w", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return nil, fmt.Errorf("create protected data directory ACL: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return nil, fmt.Errorf("read protected directory ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(dataDir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return nil, fmt.Errorf("protect Tailgate data directory (run CLI as Administrator): %w", err)
	}
	return &Protector{}, nil
}

func blob(data []byte) windows.DataBlob {
	var result windows.DataBlob
	result.Size = uint32(len(data))
	if len(data) > 0 {
		result.Data = &data[0]
	}
	return result
}

func (p *Protector) encrypt(plaintext []byte) ([]byte, error) {
	in := blob(plaintext)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

func (p *Protector) decrypt(encrypted []byte) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, errors.New("DPAPI blob is empty")
	}
	in := blob(encrypted)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	defer clear(unsafe.Slice(out.Data, int(out.Size)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}
