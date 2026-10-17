package web

import "embed"

// StaticFS embeds all web assets from the static directory into the compiled binary.
//
//go:embed static/*
var StaticFS embed.FS
