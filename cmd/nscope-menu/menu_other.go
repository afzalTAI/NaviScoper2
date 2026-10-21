//go:build !darwin

package main

import (
	"context"
	"errors"
)

func runMenu(ctx context.Context, app *menuApp) error {
	return errors.New("menu bar agent requires macOS")
}
