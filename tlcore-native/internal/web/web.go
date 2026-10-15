// Package web serves the embedded single-page management UI.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html
var files embed.FS

// Handler returns an http.Handler serving the UI at the root.
func Handler() http.Handler {
	sub, err := fs.Sub(files, ".")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
