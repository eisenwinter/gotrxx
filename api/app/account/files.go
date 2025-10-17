package account

import (
	"net/http"
	"path/filepath"
)

/*
  Disable directory listing to avoid CWE-548
*/

type noDirectoryListingFs struct {
	fs http.FileSystem
}

func (nfs noDirectoryListingFs) Open(name string) (http.File, error) {
	f, err := nfs.fs.Open(name)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if s.IsDir() {
		index := filepath.Join(name, "index.html")
		if _, err := nfs.fs.Open(index); err != nil {
			closeErr := f.Close()
			if closeErr != nil {
				return nil, closeErr
			}
			return nil, err
		}
	}

	return f, nil
}
