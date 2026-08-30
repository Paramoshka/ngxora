FROM ubuntu:22.04

ARG OPEN5GS_VERSION=v2.7.7
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bison \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        flex \
        git \
        libbson-dev \
        libcurl4-gnutls-dev \
        libgcrypt-dev \
        libgnutls28-dev \
        libidn11-dev \
        libmicrohttpd-dev \
        libmongoc-dev \
        libnghttp2-dev \
        libsctp-dev \
        libssl-dev \
        libtalloc-dev \
        libtins-dev \
        libyaml-dev \
        meson \
        ninja-build \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch "${OPEN5GS_VERSION}" --depth 1 \
        https://github.com/open5gs/open5gs.git /src/open5gs \
    && meson setup /src/open5gs/build /src/open5gs \
        --buildtype=release \
        --prefix=/opt/open5gs \
    && ninja -C /src/open5gs/build install \
    && rm -rf /src/open5gs

COPY nrf.yaml /etc/open5gs/nrf.yaml

EXPOSE 7777

CMD ["/opt/open5gs/bin/open5gs-nrfd", "-c", "/etc/open5gs/nrf.yaml"]
