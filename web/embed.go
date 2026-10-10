// Package web встраивает собранный фронтенд в бинарник демона.
// Исходники SPA появятся на этапе 8; пока в dist/ — заглушка.
package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var dist embed.FS

// Dist — содержимое каталога dist/ как корень файловой системы.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // каталог встроен при компиляции — ошибка здесь невозможна
	}
	return sub
}
