ARG VERSION=unstable
ARG GVM_LIBS_VERSION=edge
ARG DEBIAN_FRONTEND=noninteractive

FROM greenbone/gvmd-build:${VERSION} as builder

COPY . /source
WORKDIR /source

RUN mkdir /build && \
    mkdir /install && \
    cd /build && \
    cmake -DCMAKE_BUILD_TYPE=Release /source && \
    make DESTDIR=/install install

FROM greenbone/gvm-libs:${GVM_LIBS_VERSION}

ARG DEBIAN_FRONTEND=noninteractive

# Runtime dependencies

# PDF Report
# texlive-fonts-recommended
# texlive-latex-extra

# HTML Reports, cert data and scan data details
# xsltproc

# verinice report
# xsltproc
# xmlstarlet
# zip

# RPM credential packages
# rpm
# fakeroot

# DEB credential packages
# dpkg
# fakeroot

# Windows Executable (.exe) credential installer
# nsis

# signature verification
# gnupg

# HTTP alerts
# wget

# SCP alert
# sshpass
# openssh-client

# Send alert
# socat

# SNMP alert
# snmp

# SMB alert
# python3
# smbclient

# s/mime email encryption
# gpgsm

# Loading scap and cert data
# xml-twig-tools

# Required for set up certificates for GVM
# gnutls-bin

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    dpkg \
    fakeroot \
    nsis \
    gosu \
    gnupg \
    gpgsm \
    gnutls-bin \
    libbsd0 \
    libgpgme11 \
    libical3 \
    libpq5 \
    openssh-client \
    postgresql-client-13 \
    postgresql-client-common \
    python3 \
    rpm \
    rsync \
    socat \
    smbclient \
    snmp \
    sshpass \
    texlive-fonts-recommended \
    texlive-latex-extra \
    wget \
    xml-twig-tools \
    xmlstarlet \
    xsltproc \
    zip && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install/ /

COPY .docker/start-gvmd.sh /usr/local/bin/start-gvmd
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

RUN addgroup --gid 1001 --system gvmd && \
    adduser --no-create-home --shell /bin/false --disabled-password --uid 1001 --system --group gvmd

RUN mkdir -p /run/gvmd && \
    mkdir -p /var/lib/gvm && \
    mkdir -p /var/log/gvm && \
    chown -R gvmd:gvmd /etc/gvm && \
    chown -R gvmd:gvmd /run/gvmd && \
    chown -R gvmd:gvmd /var/lib/gvm && \
    chown -R gvmd:gvmd /var/log/gvm && \
    chmod 755 /usr/local/bin/entrypoint && \
    chmod 755 /usr/local/bin/start-gvmd

ENTRYPOINT [ "/usr/local/bin/entrypoint" ]

CMD [ "/usr/local/bin/start-gvmd" ]
