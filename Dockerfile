FROM rust:1-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release -p capsule-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/capsule-server /app/capsule-server
COPY crates/capsule-server/static /app/static
ENV CAPSULE_STATIC_DIR=/app/static
EXPOSE 3000
CMD ["/app/capsule-server"]
