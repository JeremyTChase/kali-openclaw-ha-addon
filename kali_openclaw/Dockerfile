FROM kalilinux/kali-rolling

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# ---- Layer 1: Kali headless tools (largest layer, cached) ----
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      kali-linux-headless \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ---- Layer 2: Build and runtime deps ----
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      jq \
      ripgrep \
      nano \
      unzip \
      openssh-server \
      python3-pip \
      make \
      g++ \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ---- Layer 3: Node.js 24.x ----
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ---- Layer 4: pnpm + OpenClaw ----
ENV PNPM_HOME=/pnpm
ENV PATH="${PNPM_HOME}:${PATH}"

RUN npm install -g pnpm && \
    mkdir -p /pnpm && \
    pnpm config set global-bin-dir /pnpm && \
    pnpm add -g clawdhub undici

# ---- Layer 5: gog CLI (Google Workspace) ----
ARG GOG_VERSION=0.6.1
ARG TARGETARCH
RUN ARCH=$(echo ${TARGETARCH:-$(uname -m)} | sed 's/aarch64/arm64/;s/x86_64/amd64/') && \
    curl -fsSL "https://github.com/steipete/gogcli/releases/download/v${GOG_VERSION}/gogcli_${GOG_VERSION}_linux_${ARCH}.tar.gz" \
      | tar xz -C /usr/local/bin gog && \
    chmod +x /usr/local/bin/gog

# ---- Layer 6: homeassistant-cli ----
RUN pip3 install --no-cache-dir --break-system-packages homeassistant-cli

WORKDIR /opt/openclaw

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD [ "/run.sh" ]
