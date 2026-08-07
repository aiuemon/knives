package storage

import "errors"

// ErrNotFound is returned by Store methods that look up a single row when
// no matching row exists.
var ErrNotFound = errors.New("storage: not found")
