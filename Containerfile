# Image for OpenBao's declarative plugin configuration (the `plugin` stanza in
# the server configuration), which downloads the plugin from an OCI registry.
#
# OpenBao flattens the image and looks for the plugin binary at its root, so the
# image contains only that file. It is built by scripts/image from the release
# archives; see `make image`.

FROM scratch
ARG TARGETOS
ARG TARGETARCH

LABEL org.opencontainers.image.title="openbao-plugin-secrets-oauthapp"
LABEL org.opencontainers.image.description="OAuth 2.0 secrets engine plugin for OpenBao"
LABEL org.opencontainers.image.source="https://github.com/openbao/openbao-plugin-secrets-oauthapp"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY ${TARGETOS}-${TARGETARCH}/openbao-plugin-secrets-oauthapp /openbao-plugin-secrets-oauthapp

# OpenBao 2.5 and 2.6 require `binary_name` in the plugin stanza; 2.7 and later
# infer it from the entrypoint when it is omitted.
ENTRYPOINT ["/openbao-plugin-secrets-oauthapp"]
