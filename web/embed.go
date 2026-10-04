// Package webassets embeds the complete offline frontend into the executable.
package webassets

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html app.css app.js favicon.svg vendor
var files embed.FS

// Handler serves only the packaged frontend. No external assets are required.
func Handler() http.Handler {
	static, err := fs.Sub(files, ".")
	if err != nil {
		panic("embedded frontend is unavailable: " + err.Error())
	}
	return http.FileServer(http.FS(static))
}
