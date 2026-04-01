# Build the daemon
FROM debian:stable-slim AS buildenv

ENV APT_PACKAGES build-essential ca-certificates curl
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends ${APT_PACKAGES}

RUN useradd --system --uid=10000 rust
USER rust
WORKDIR /home/rust/

RUN curl --tlsv1.3 --output rustup.sh https://sh.rustup.rs \
    && sh rustup.sh -y --profile minimal
RUN .cargo/bin/rustup target add `uname -m`-unknown-linux-musl

COPY --chown=rust:rust ./ app/
RUN .cargo/bin/cargo install --target=`uname -m`-unknown-linux-musl --path=app --bin=wgproxy


# Minimal environment to run the static application
FROM scratch
COPY --from=buildenv /home/rust/.cargo/bin/wgproxy /

USER 10000:10000
ENTRYPOINT [ "/wgproxy" ]
