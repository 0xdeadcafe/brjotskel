ARG BRJOTSKEL_BASE_IMAGE=debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
FROM ${BRJOTSKEL_BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive
ARG BRJOTSKEL_BASE_IMAGE
ARG NETEXEC_COMMIT=c7dc286ba65daf10402cdc470e531b84e6d3d911
ARG NODE_VERSION=24.19.0
ARG NODE_LINUX_X64_SHA256=14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647
ARG NODE_LINUX_ARM64_SHA256=01443c1e1a29e531ccad5a46fefa6df490d2189c49f7955904aecdbb0fe86fdc
ARG PI_CODING_AGENT_VERSION=0.83.0
ARG PI_SMART_FETCH_VERSION=0.3.12
ARG POWERSHELL_VERSION=7.6.5-1.deb
ARG RUST_TOOLCHAIN=1.91.1
ARG BRJOTSKEL_UID=1000
ARG BRJOTSKEL_GID=1000
ARG BRJOTSKEL_BUILD_REF=unknown
ARG BRJOTSKEL_BUILD_DATE=unknown
ARG BRJOTSKEL_BUILD_URL=unknown
LABEL version="0.3.0" \
      description="AI-native incident response harness" \
      maintainer="brjotskel" \
      org.opencontainers.image.title="brjotskel" \
      org.opencontainers.image.description="AI-native incident response harness" \
      org.opencontainers.image.version="0.3.0" \
      org.opencontainers.image.base.name="${BRJOTSKEL_BASE_IMAGE}" \
      org.opencontainers.image.revision="${BRJOTSKEL_BUILD_REF}" \
      org.opencontainers.image.created="${BRJOTSKEL_BUILD_DATE}" \
      org.opencontainers.image.url="https://github.com/0xdeadcafe/brjotskel" \
      org.opencontainers.image.source="https://github.com/0xdeadcafe/brjotskel"

# --- Base system packages ---
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        apt-transport-https \
        openssh-client \
        sshpass \
        ncat \
        nmap \
        proxychains4 \
        jq \
        git \
        ripgrep \
        fd-find \
        fzf \
        python3 \
        python3-pip \
        python3-yaml \
        less \
        neovim \
        iputils-ping \
        dnsutils \
        netcat-openbsd \
        xz-utils \
    && ln -sf /usr/bin/fdfind /usr/local/bin/fd \
    && install -d -m 0755 /etc/apt/keyrings \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg \
    && chmod go+r /etc/apt/keyrings/microsoft.gpg \
    && . /etc/os-release \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/microsoft-prod.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends powershell=${POWERSHELL_VERSION} \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Runtime user ---
RUN set -eux; \
    if ! getent group "${BRJOTSKEL_GID}" >/dev/null; then \
      groupadd --gid "${BRJOTSKEL_GID}" brjotskel; \
    fi; \
    useradd --uid "${BRJOTSKEL_UID}" --gid "${BRJOTSKEL_GID}" --create-home --shell /bin/bash brjotskel; \
    install -d -m 0700 -o brjotskel -g "${BRJOTSKEL_GID}" /home/brjotskel/.ssh

# --- Python harness tools: Impacket, NetExec, and transitive deps pinned ---
COPY requirements-harness.txt /tmp/requirements-harness.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && export RUSTUP_HOME=/tmp/rustup CARGO_HOME=/tmp/cargo PATH=/tmp/cargo/bin:$PATH \
    && curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
    && pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements-harness.txt \
    && pip3 install --no-cache-dir --break-system-packages --no-deps --no-build-isolation "git+https://github.com/Pennyw0rth/NetExec@${NETEXEC_COMMIT}" \
    && if command -v netexec >/dev/null 2>&1; then \
         true; \
       elif command -v nxc >/dev/null 2>&1; then \
         ln -sf "$(command -v nxc)" /usr/local/bin/netexec; \
       else \
         echo 'NetExec installation did not provide netexec or nxc' >&2; \
         exit 1; \
       fi \
    && (netexec --version || netexec --help >/dev/null) \
    && rm -f /tmp/requirements-harness.txt \
    && rm -rf /root/.nxc /root/.netexec /tmp/rustup /tmp/cargo \
    && apt-get purge -y --auto-remove build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Node.js (for pi agent / extensions) ---
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) node_arch="x64"; node_sha="${NODE_LINUX_X64_SHA256}" ;; \
      arm64) node_arch="arm64"; node_sha="${NODE_LINUX_ARM64_SHA256}" ;; \
      *) echo "Unsupported Node.js architecture: $arch" >&2; exit 1 ;; \
    esac; \
    node_dist="node-v${NODE_VERSION}-linux-${node_arch}"; \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${node_dist}.tar.xz"; \
    echo "${node_sha}  ${node_dist}.tar.xz" | sha256sum -c -; \
    tar -xJf "${node_dist}.tar.xz" -C /usr/local --strip-components=1; \
    rm "${node_dist}.tar.xz"; \
    node --version; \
    npm --version

# --- pi coding agent ---
RUN npm install -g "@earendil-works/pi-coding-agent@${PI_CODING_AGENT_VERSION}" \
    && pi --version

# --- Project layout ---
WORKDIR /opt/brjotskel

COPY bin/ /opt/brjotskel/bin/
RUN chmod +x /opt/brjotskel/bin/ir-log /opt/brjotskel/bin/intel-snippet /opt/brjotskel/bin/netexec-to-intel /opt/brjotskel/bin/check-playbook-inventory /opt/brjotskel/bin/check-playbook-contracts /opt/brjotskel/bin/check-tool-inventory /opt/brjotskel/bin/build-manifest /opt/brjotskel/bin/image-sbom /opt/brjotskel/bin/clean-local /opt/brjotskel/bin/ir-search /opt/brjotskel/bin/ir-report /opt/brjotskel/bin/ir-package /opt/brjotskel/bin/test /opt/brjotskel/bin/smoke-check \
    && ln -sf /opt/brjotskel/bin/ir-log /usr/local/bin/ir-log \
    && ln -sf /opt/brjotskel/bin/intel-snippet /usr/local/bin/intel-snippet \
    && ln -sf /opt/brjotskel/bin/netexec-to-intel /usr/local/bin/netexec-to-intel \
    && ln -sf /opt/brjotskel/bin/check-playbook-inventory /usr/local/bin/check-playbook-inventory \
    && ln -sf /opt/brjotskel/bin/check-playbook-contracts /usr/local/bin/check-playbook-contracts \
    && ln -sf /opt/brjotskel/bin/check-tool-inventory /usr/local/bin/check-tool-inventory \
    && ln -sf /opt/brjotskel/bin/build-manifest /usr/local/bin/build-manifest \
    && ln -sf /opt/brjotskel/bin/image-sbom /usr/local/bin/image-sbom \
    && ln -sf /opt/brjotskel/bin/clean-local /usr/local/bin/clean-local \
    && ln -sf /opt/brjotskel/bin/ir-search /usr/local/bin/ir-search \
    && ln -sf /opt/brjotskel/bin/ir-report /usr/local/bin/ir-report \
    && ln -sf /opt/brjotskel/bin/ir-package /usr/local/bin/ir-package

COPY CONSTITUTION.md README.md /opt/brjotskel/
COPY docs/ /opt/brjotskel/docs/

# --- pi skills & extensions (inside container) ---
# Copy only tracked pi configuration. Do not copy .pi/npm local cache/node_modules.
RUN mkdir -p /opt/brjotskel/.pi /opt/brjotskel/.pi/prompts /opt/brjotskel/.pi/npm
COPY .pi/settings.json /opt/brjotskel/.pi/settings.json
COPY .pi/prompts/ /opt/brjotskel/.pi/prompts/
COPY .pi/extensions/ /opt/brjotskel/.pi/extensions/
COPY .pi/skills/ /opt/brjotskel/.pi/skills/
COPY .config/nvim/ /etc/xdg/nvim/

RUN mkdir -p /opt/brjotskel/logs /opt/brjotskel/logs/remote-sessions /opt/brjotskel/workspace /workspace /home/brjotskel/.config \
    && cd /opt/brjotskel \
    && pi install -l --approve "npm:pi-smart-fetch@${PI_SMART_FETCH_VERSION}" \
    && BRJOTSKEL_BASE_IMAGE="${BRJOTSKEL_BASE_IMAGE}" \
       BRJOTSKEL_BUILD_REF="${BRJOTSKEL_BUILD_REF}" \
       BRJOTSKEL_BUILD_DATE="${BRJOTSKEL_BUILD_DATE}" \
       BRJOTSKEL_BUILD_URL="${BRJOTSKEL_BUILD_URL}" \
       BRJOTSKEL_UID="${BRJOTSKEL_UID}" \
       BRJOTSKEL_GID="${BRJOTSKEL_GID}" \
       NETEXEC_COMMIT="${NETEXEC_COMMIT}" \
       NODE_VERSION="${NODE_VERSION}" \
       NODE_LINUX_X64_SHA256="${NODE_LINUX_X64_SHA256}" \
       NODE_LINUX_ARM64_SHA256="${NODE_LINUX_ARM64_SHA256}" \
       PI_CODING_AGENT_VERSION="${PI_CODING_AGENT_VERSION}" \
       PI_SMART_FETCH_VERSION="${PI_SMART_FETCH_VERSION}" \
       POWERSHELL_VERSION="${POWERSHELL_VERSION}" \
       RUST_TOOLCHAIN="${RUST_TOOLCHAIN}" \
       /opt/brjotskel/bin/build-manifest /opt/brjotskel/BUILD-MANIFEST.json \
    && rm -rf /root/.nxc /root/.netexec \
    && chown -R root:root /opt/brjotskel/bin /opt/brjotskel/docs /opt/brjotskel/.pi /etc/xdg/nvim /opt/brjotskel/CONSTITUTION.md /opt/brjotskel/README.md /opt/brjotskel/BUILD-MANIFEST.json \
    && chmod 0644 /opt/brjotskel/BUILD-MANIFEST.json \
    && chmod -R go-w /opt/brjotskel/bin /opt/brjotskel/docs /opt/brjotskel/.pi /etc/xdg/nvim \
    && chgrp "${BRJOTSKEL_GID}" /opt/brjotskel/.pi \
    && chmod 1775 /opt/brjotskel/.pi \
    && chown -R "${BRJOTSKEL_UID}:${BRJOTSKEL_GID}" /opt/brjotskel/logs /opt/brjotskel/workspace /workspace /home/brjotskel/.config /home/brjotskel/.ssh \
    && chmod 0750 /opt/brjotskel/logs /opt/brjotskel/logs/remote-sessions /opt/brjotskel/workspace /workspace

ENV BRJOTSKEL_LOG_DIR=/opt/brjotskel/logs
ENV BRJOTSKEL_INTEL_DIR=/opt/brjotskel/workspace/intel
ENV PI_CODING_AGENT_SESSION_DIR=/opt/brjotskel/workspace/pi-sessions
ENV HOME=/home/brjotskel

USER brjotskel
WORKDIR /opt/brjotskel

CMD ["pi"]
