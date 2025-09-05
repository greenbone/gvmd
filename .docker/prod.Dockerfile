ARG GVM_LIBS_VERSION=stable
ARG DEBIAN_FRONTEND=noninteractive
# when set it will added to the cmake command
# As an example:
# FEATURE_TOGGLES="-DOPENVASD=1"
# enables openvasd feature toggle.
ARG FEATURE_TOGGLE=""

FROM registry.community.greenbone.net/community/gvm-libs:${GVM_LIBS_VERSION} AS builder
ARG FEATURE_TOGGLE

COPY . /source
WORKDIR /source

RUN sh /source/.github/install-dependencies.sh \
    /source/.github/build-dependencies.list \
    && rm -rf /var/lib/apt/lists/*

RUN cmake -DCMAKE_BUILD_TYPE=Release ${FEATURE_TOGGLE} -B/build /source && \
    DESTDIR=/install cmake --build /build -j$(nproc) -- install

FROM registry.community.greenbone.net/community/gvm-libs:${GVM_LIBS_VERSION}

ARG DEBIAN_FRONTEND=noninteractive

RUN --mount=type=bind,source=.github,target=/source/ \
    sh /source/install-dependencies.sh /source/runtime-dependencies.list \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install/ /

COPY .docker/start-gvmd.sh /usr/local/bin/start-gvmd
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint
COPY .docker/setup-mta.sh /usr/local/bin/setup-mta

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
