// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoytls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/model"
)

func TestDownstreamTLSHandshakeSignatures(t *testing.T) {
	socket := toTransportSocket("cilium-secrets", []model.TLSSecret{{Name: "gateway-cert", Namespace: "gateway"}}, nil)
	context := &envoytls.DownstreamTlsContext{}
	require.NoError(t, socket.GetTypedConfig().UnmarshalTo(context))
	common := context.GetCommonTlsContext()
	require.NotNil(t, common)
	require.NotNil(t, common.GetTlsParams())
	require.Equal(t, envoytls.TlsParameters_TLSv1_2, common.TlsParams.TlsMinimumProtocolVersion)
	// Independent policy expectation: neither SHA-1 nor SHA-224 is permitted.
	require.Equal(t, []string{
		"ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512",
		"rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512",
		"rsa_pkcs1_sha256", "rsa_pkcs1_sha384", "rsa_pkcs1_sha512", "ed25519",
	}, common.TlsParams.SignatureAlgorithms)
	require.Len(t, common.TlsCertificateSdsSecretConfigs, 1)
	require.Equal(t, "cilium-secrets/cilium-sync-secret-49c51718df79f249150d1fa595a149ce110851050da7d10be73e0c03c47378d9", common.TlsCertificateSdsSecretConfigs[0].Name)
	require.Nil(t, common.TlsCertificateSdsSecretConfigs[0].SdsConfig)
	require.Equal(t, envoytls.TlsParameters_TLS_AUTO, common.TlsParams.TlsMaximumProtocolVersion)
}
