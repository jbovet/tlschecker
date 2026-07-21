# syntax=docker/dockerfile:1.25
FROM rust:1.97-slim-bookworm AS build
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential perl pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && printf 'fn main() {}\n' > src/main.rs
RUN cargo build --release --locked

COPY src ./src
RUN cargo build --release --locked && strip target/release/tlschecker

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 42000 hoare && \
    useradd --uid 42000 --gid hoare --create-home --shell /usr/sbin/nologin hoare

COPY --from=build /src/target/release/tlschecker /usr/local/bin/tlschecker
RUN chown hoare:hoare /usr/local/bin/tlschecker && chmod 755 /usr/local/bin/tlschecker

USER hoare
ENTRYPOINT ["/usr/local/bin/tlschecker"]