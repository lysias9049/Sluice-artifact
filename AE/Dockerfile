FROM rust:1.96.0-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends python3 time ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/sluice
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --locked --release && cargo test --locked --release --no-run
# The runtime uses the host UID/GID. Cargo still needs writable cache/lock
# files when executing already-built tests; these paths stay inside the image.
RUN chmod -R a+rwX target /usr/local/cargo
COPY AE ./AE
COPY LICENSE ./LICENSE
ENV PYTHONUNBUFFERED=1
CMD ["python3", "AE/worker.py", "--help"]
