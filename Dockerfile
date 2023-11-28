FROM rust:1 AS chef
RUN cargo install cargo-chef
WORKDIR app

FROM chef AS planner
COPY Cargo.toml Cargo.lock .
COPY src/ src/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN apt-get update
RUN apt-get install -y protobuf-compiler
RUN cargo chef cook --release --recipe-path recipe.json
COPY Cargo.toml Cargo.lock .
COPY src/ src/
COPY build.rs build.rs
RUN cargo build --release --bin recert

FROM docker.io/library/debian:bookworm AS runtime
WORKDIR app
RUN apt-get update
RUN apt-get install -y openssl
COPY --from=builder /app/target/release/recert /usr/local/bin
RUN ln -s /usr/local/bin/recert /usr/local/bin/ocp-rename
ENTRYPOINT ["/usr/local/bin/recert"]
