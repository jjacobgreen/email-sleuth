# Running Email Sleuth in Docker

Build the container image from the repo root:

```bash
docker build -t email-sleuth:latest .
```

Start an interactive shell (default entrypoint is `bash`) with your workspace mounted:

```bash
docker run --rm -it \
  -v "$(pwd)":/workspace \
  -w /workspace \
  -v "$(pwd)/data":/data \
  email-sleuth:latest
```

Inside the container:

- Use `email-sleuth` or the `es` alias (both are on `PATH`).
  - Example usage: `es --name "John Doe" --domain "example.com"`
- Config defaults to `/etc/email-sleuth/config.toml`; override with `EMAIL_SLEUTH_CONFIG`.
- Place inputs/outputs under `/data` or bind other directories as needed.
