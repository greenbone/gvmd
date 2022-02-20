ARG VERSION=stable
ARG DEBIAN_FRONTEND=noninteractive

FROM greenbone/gvmd-build:${VERSION} as build

# Install
COPY . /source
RUN cmake -DCMAKE_BUILD_TYPE=Release -B/build /source
RUN DESTDIR=/install cmake --build /build -- install 

FROM greenbone/gvm-libs:${VERSION}

ARG DEBIAN_FRONTEND=noninteractive

# Install Runtime dependencies

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

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    dpkg \
    fakeroot \
    gosu \
    gnupg \
    gpgsm \
    libgpgme11 \
    libical3 \
    libpq5 \
    openssh-client \
    postgresql-client-13 \
    postgresql-client-common \
    python3 \
    rpm \
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

COPY --from=build /install/ /
COPY .docker/start-gvmd.sh /usr/local/bin/start-gvmd
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

RUN addgroup --gid 1001 --system gvmd \
    && adduser --no-create-home --shell /bin/false --disabled-password \
    --uid 1001 --system --group gvmd

RUN mkdir -p /run/gvmd /var/lib/gvm /var/log/gvm \
    && chown -R gvmd:gvmd /etc/gvm /run/gvmd /var/lib/gvm /var/log/gvm \
    && chmod 755 /usr/local/bin/entrypoint /usr/local/bin/start-gvmd

ENTRYPOINT [ "/usr/local/bin/entrypoint" ]

CMD [ "/usr/local/bin/start-gvmd" ]
