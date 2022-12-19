FROM rust:1.66 as build
LABEL maintainer="jose.bovet@gmail.com"

RUN cargo new --bin tlschecker
WORKDIR /tlschecker

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# cache deps
RUN cargo build --release
RUN rm src/*.rs

COPY ./src ./src

# build for release
RUN rm ./target/release/deps/tlschecker*
RUN cargo build --release

# base
FROM rust:1.66-slim-buster

# copy the build artifact from the build stage
COPY --from=build /tlschecker/target/release/tlschecker .

# create and set non-root USER
RUN addgroup --gid 42000 hoare && \
    useradd --uid 42000 --gid hoare hoare
RUN chown -R hoare:hoare tlschecker && \
    chmod 755 tlschecker
USER hoare

ENTRYPOINT ["./tlschecker"]