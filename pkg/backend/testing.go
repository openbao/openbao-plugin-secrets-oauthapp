// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func CreateBackendWithStorage(t *testing.T, opts Options) (*backend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := New(opts)
	require.NoError(t, err, "failed to create backend")

	err = b.Setup(t.Context(), config)
	require.NoError(t, err, "failed to setup backend")

	err = b.Initialize(t.Context(), &logical.InitializationRequest{
		Storage: config.StorageView,
	})
	require.NoError(t, err, "unable to initialize backend")

	t.Cleanup(func() {
		b.Cleanup(t.Context())
	})

	return b.(*backend), config.StorageView
}
