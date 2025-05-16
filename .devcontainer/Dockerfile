FROM registry.community.greenbone.net/community/gvm-libs:edge

ARG DEBIAN_FRONTEND=noninteractive
ARG CGREEN_VERSION=1.6.2
ARG CGREEN_HASH=fe6be434cbe280330420106bd5d667f1bc84ae9468960053100dbf17071036b9

ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# install dependencies
RUN --mount=type=bind,source=.github,target=/source/ \
    sh /source/install-dependencies.sh /source/build-dependencies.list
RUN apt-get install -y --no-install-recommends \
    clang-format

# add non-root user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash \
    && apt-get update \
    && apt-get install -y --no-install-recommends sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# install cgreen
RUN curl -sSL -o cgreen.tar.gz https://github.com/cgreen-devs/cgreen/archive/refs/tags/$CGREEN_VERSION.tar.gz \
    && echo "$CGREEN_HASH cgreen.tar.gz" | sha256sum -c - \
    && tar -xzf cgreen.tar.gz \
    && cd cgreen-* \
    && cmake -Bbuild -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j$(nproc) -- install \
    && ldconfig

CMD ["/bin/bash"]
