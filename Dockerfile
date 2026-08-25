FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive
LABEL version="0.3.0" \
      description="AI-native incident response harness" \
      maintainer="brjotskel"

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
    && ln -sf /usr/bin/fdfind /usr/local/bin/fd \
    && install -d -m 0755 /etc/apt/keyrings \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg \
    && chmod go+r /etc/apt/keyrings/microsoft.gpg \
    && . /etc/os-release \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/microsoft-prod.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends powershell \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Impacket & NetExec ---
RUN pip3 install --no-cache-dir --break-system-packages impacket
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && export RUSTUP_HOME=/tmp/rustup CARGO_HOME=/tmp/cargo PATH=/tmp/cargo/bin:$PATH \
    && curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable \
    && pip3 install --no-cache-dir --break-system-packages git+https://github.com/Pennyw0rth/NetExec \
    && if command -v netexec >/dev/null 2>&1; then \
         true; \
       elif command -v nxc >/dev/null 2>&1; then \
         ln -sf "$(command -v nxc)" /usr/local/bin/netexec; \
       else \
         echo 'NetExec installation did not provide netexec or nxc' >&2; \
         exit 1; \
       fi \
    && (netexec --version || netexec --help >/dev/null) \
    && rm -rf /root/.nxc /root/.netexec /tmp/rustup /tmp/cargo \
    && apt-get purge -y --auto-remove build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Node.js (for pi agent / extensions) ---
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- pi coding agent ---
RUN npm install -g @earendil-works/pi-coding-agent

# --- Project layout ---
WORKDIR /opt/brjotskel

COPY bin/ /opt/brjotskel/bin/
RUN chmod +x /opt/brjotskel/bin/ir-log /opt/brjotskel/bin/intel-snippet /opt/brjotskel/bin/ir-search /opt/brjotskel/bin/ir-report /opt/brjotskel/bin/test /opt/brjotskel/bin/smoke-check \
    && ln -sf /opt/brjotskel/bin/ir-log /usr/local/bin/ir-log \
    && ln -sf /opt/brjotskel/bin/intel-snippet /usr/local/bin/intel-snippet \
    && ln -sf /opt/brjotskel/bin/ir-search /usr/local/bin/ir-search \
    && ln -sf /opt/brjotskel/bin/ir-report /usr/local/bin/ir-report

COPY CONSTITUTION.md README.md /opt/brjotskel/
COPY docs/ /opt/brjotskel/docs/

# --- pi skills & extensions (inside container) ---
# Copy only tracked pi configuration. Do not copy .pi/npm local cache/node_modules.
RUN mkdir -p /opt/brjotskel/.pi /opt/brjotskel/.pi/prompts /opt/brjotskel/.pi/npm
COPY .pi/settings.json /opt/brjotskel/.pi/settings.json
COPY .pi/extensions/ /opt/brjotskel/.pi/extensions/
COPY .pi/skills/ /opt/brjotskel/.pi/skills/
COPY .config/nvim/ /etc/xdg/nvim/

RUN mkdir -p /opt/brjotskel/logs /opt/brjotskel/logs/remote-sessions /opt/brjotskel/workspace /workspace \
    && cd /opt/brjotskel \
    && pi install -l --approve npm:pi-smart-fetch

ENV BRJOTSKEL_LOG_DIR=/opt/brjotskel/logs
ENV BRJOTSKEL_INTEL_DIR=/opt/brjotskel/workspace/intel

WORKDIR /opt/brjotskel

CMD ["pi"]
