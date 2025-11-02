// Package signer provides implementations of the signer interface from
// next.orly.dev/pkg/interfaces/signer, used to abstract the signature algorithm
// from the usage.
package signer

import (
	orlysigner "next.orly.dev/pkg/interfaces/signer"
)

// I is an alias for the signer interface from next.orly.dev/pkg/interfaces/signer.
// This allows this package to be used as a drop-in replacement in orly.
type I = orlysigner.I

// Gen is an alias for the Gen interface from next.orly.dev/pkg/interfaces/signer.
// This allows this package to be used as a drop-in replacement in orly.
type Gen = orlysigner.Gen
