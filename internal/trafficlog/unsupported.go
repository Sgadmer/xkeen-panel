//go:build !((linux && (amd64 || arm64)) || (windows && amd64))

package trafficlog

import (
	"context"
	"errors"
)

// Unsupported architectures keep the normal panel and live journal without
// linking the optional database engine into their binary.
type Store struct{}

func Supported() bool { return false }
func SupportReason() string {
	return "суточная история на диске пока не поддерживается этой архитектурой; текущие соединения доступны"
}
func openStore(context.Context, string, Options) (*Store, error) {
	return nil, errors.New(SupportReason())
}
func (*Store) Submit(Entry) bool                          { return false }
func (*Store) Status() Status                             { return Status{Error: SupportReason()} }
func (*Store) Flush(context.Context) error                { return errors.New(SupportReason()) }
func (*Store) Query(context.Context, Query) (Page, error) { return Page{}, errors.New(SupportReason()) }
func (*Store) Devices(context.Context) ([]Device, error)  { return []Device{}, nil }
func (*Store) Close() error                               { return nil }
