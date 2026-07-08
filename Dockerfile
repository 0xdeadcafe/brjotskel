FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

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
        python3 \
        python3-pip \
        python3-yaml \
        less \
        neovim \
        iputils-ping \
        dnsutils \
        netcat-openbsd \
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
RUN pip3 install --no-cache-dir --break-system-packages impacket \
    && pip3 install --no-cache-dir --break-system-packages git+https://github.com/Pennyw0rth/NetExec 2>/dev/null \
    || echo 'NetExec install skipped — install manually if needed'

# --- Node.js (for pi agent / extensions) ---
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- pi coding agent ---
RUN npm install -g @earendil-works/pi-coding-agent

# --- Project layout ---
WORKDIR /opt/brjotskel

COPY bin/ir-log /usr/local/bin/ir-log
COPY bin/intel-snippet /usr/local/bin/intel-snippet
RUN chmod +x /usr/local/bin/ir-log /usr/local/bin/intel-snippet

COPY CONSTITUTION.md README.md /opt/brjotskel/
COPY docs/ /opt/brjotskel/docs/

# --- pi skill & extension (inside container) ---
COPY .pi/ /opt/brjotskel/.pi/
COPY .config/nvim/ /etc/xdg/nvim/

RUN mkdir -p /opt/brjotskel/logs /opt/brjotskel/logs/remote-sessions /workspace \
    && cd /opt/brjotskel \
    && pi install -l --approve npm:pi-smart-fetch

ENV BRJOTSKEL_LOG_DIR=/opt/brjotskel/logs

WORKDIR /workspace

CMD ["bash"]
