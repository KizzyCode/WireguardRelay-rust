# Build the daemon
FROM debian:stable-slim AS buildenv

ENV APT_PACKAGES build-essential ca-certificates curl git
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends ${APT_PACKAGES}

RUN useradd --system --uid=10000 rust
USER rust
WORKDIR /home/rust/

RUN curl --tlsv1.3 --output rustup.sh https://sh.rustup.rs \
    && sh rustup.sh -y --profile minimal
COPY --chown=rust:rust ./ ws2812b.cgi/
RUN .cargo/bin/cargo install wgproxy


# Build the real container
FROM debian:stable-slim

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get clean


COPY --from=buildenv --chown=root:root /home/rust/.cargo/bin/wgproxy /usr/bin/

RUN useradd --system --shell=/usr/sbin/nologin --uid=10000 wgproxy

USER wgproxy
CMD ["/usr/bin/wgproxy"]
