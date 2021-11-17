ARG VERSION=oldstable
ARG DEBIAN_FRONTEND=noninteractive

FROM greenbone/gvm-libs:${VERSION} as builder

# Install Debian core dependencies required for building gvm with PostgreSQL
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libglib2.0-dev \
    libgnutls28-dev \
    libgpgme-dev \
    libpq-dev \
    libical-dev \
    postgresql-server-dev-13 \
    xml-twig-tools \
    xsltproc && \
    rm -rf /var/lib/apt/lists/*

COPY . /source
WORKDIR /source

RUN mkdir /build && \
    mkdir /install && \
    cd /build && \
    cmake -DCMAKE_BUILD_TYPE=Release /source && \
    make DESTDIR=/install install

FROM greenbone/gvm-libs:${VERSION}

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libgpgme11 \
    libical3 \
    libpq5 \
    postgresql-client-13 \
    postgresql-client-common \
    xml-twig-tools && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install/ /

COPY .docker/start-gvmd.sh /usr/local/bin/start-gvmd

RUN addgroup --gid 1001 --system gvmd && \
    adduser --no-create-home --shell /bin/false --disabled-password --uid 1001 --system --group gvmd

RUN mkdir -p /run/gvmd && \
    mkdir -p /var/log/gvm && \
    chown -R gvmd:gvmd /etc/gvm && \
    chown -R gvmd:gvmd /run/gvmd && \
    chown -R gvmd:gvmd /var/lib/gvm && \
    chown -R gvmd:gvmd /var/log/gvm && \
    chmod 755 /usr/local/bin/start-gvmd

USER gvmd

CMD [ "/usr/local/bin/start-gvmd" ]
