package main

import "embed"

//go:embed web/dist/*
var webDist embed.FS
