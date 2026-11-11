# Exception Guardian's CLI in a container. Keys are passed at run time, never built in:
#   docker build -t exception-guardian .
#   docker run --rm exception-guardian demo --out /tmp/demo
#   docker run --rm --env-file .env -v "$PWD/out:/app/out" -v "$PWD/guardian.live.yaml:/app/guardian.live.yaml:ro" \
#       exception-guardian recheck --config guardian.live.yaml --runs out/
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY guardian.yaml ./
COPY samples ./samples
COPY maps ./maps
RUN useradd --create-home guardian && mkdir -p /app/out && chown guardian /app/out
USER guardian
ENTRYPOINT ["exception-guardian"]
CMD ["--help"]
