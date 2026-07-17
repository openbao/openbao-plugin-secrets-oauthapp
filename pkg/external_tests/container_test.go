package external_tests

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const configFmt = `
plugin "secret" "openbao-plugin-secrets-oauthapp" {
	command = "openbao-plugin-secrets-oauthapp"
	version = "v3.0.0"
	sha256sum = "%v"
}

plugin_auto_register = true
plugin_directory = "/openbao/plugins"

`

func TestCluster(t *testing.T) {
	pluginBinary := api.ReadBaoVariable("BAO_PLUGIN_BINARY")
	if pluginBinary == "" {
		t.Skip("only running docker test when $BAO_PLUGIN_BINARY present")
	}

	// Compute this plugin binary's checksum.
	pluginFile, err := os.Open(pluginBinary)
	require.NoError(t, err, "failed to open plugin binary from %v", pluginBinary)
	hash := sha256.New()

	_, err = io.Copy(hash, pluginFile)
	require.NoError(t, err, "unable to compute plugin binary checksum")

	checksumRaw := hash.Sum(nil)
	checksum := hex.EncodeToString(checksumRaw)

	// Build a config entry for this plugin.
	testDir := t.TempDir()
	configPath := filepath.Join(testDir, "oauthapp.hcl")

	err = os.WriteFile(configPath, []byte(fmt.Sprintf(configFmt, checksum)), 0o660) //gosec:disable G306 - needs to be group readable for the config to be read
	require.NoError(t, err, "failed to write plugin config to test dir")

	// Start a three-node cluster.
	opts := &docker.DockerClusterOptions{
		ImageRepo:   "quay.io/openbao/openbao",
		ImageTag:    "latest",
		NetworkName: "",
		CopyFromTo: map[string]string{
			pluginBinary: "/openbao/plugins/openbao-plugin-secrets-oauthapp",
			configPath:   "/openbao/config/oauthapp.hcl",
		},
		ClusterOptions: testcluster.ClusterOptions{
			NumCores: 3,
			VaultNodeConfig: &testcluster.VaultNodeConfig{
				LogLevel: "TRACE",
			},
		},

		// Resolves issue in https://github.com/openbao/openbao/pull/3499. Can
		// be dropped once we're on sdk/v2.6.2 tag.
		Root: true,
	}
	cluster := docker.NewTestDockerCluster(t, opts)
	defer cluster.Cleanup()

	// Leader is always in the first index.
	client := cluster.Nodes()[0].APIClient()

	// Mount our plugin.
	err = client.Sys().MountWithContext(t.Context(), "oauthapp", &api.MountInput{
		Type: "openbao-plugin-secrets-oauthapp",
	})
	require.NoError(t, err)

	// Read the configuration endpoint; it should be empty.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		for index, node := range cluster.Nodes() {
			nodeClient := node.APIClient()
			resp, err := nodeClient.Logical().ReadWithContext(t.Context(), "oauthapp/config")
			require.NoError(collect, err, "failed reading on node %v", index)
			require.Nil(collect, resp, "non-nil response on node %v", index)

			help, err := nodeClient.Help("oauthapp/config")
			require.NoError(collect, err, "failed reading help info on node %v", index)
			require.NotNil(collect, help, "got empty help response on node %v", index)
			require.Contains(collect, help.Help, "tune_reap_revoked_seconds", "help response did not contain expected parameter on node %v", index)
		}
	}, 15*time.Second, 100*time.Millisecond)
}
