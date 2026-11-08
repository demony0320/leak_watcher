# Runtime stage image. Closed network: build once where pip works (or point PIP_INDEX_URL at the internal mirror),
# then `docker save leakwatch:0.2 | gzip > leakwatch.tar.gz` and `docker load` inside.
FROM python:3.12-slim

ARG EXTRAS=db
ARG PIP_INDEX_URL
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 leakwatch

WORKDIR /app
COPY pyproject.toml ./
COPY leakwatch ./leakwatch
RUN pip install ".${EXTRAS:+[$EXTRAS]}"

USER leakwatch
WORKDIR /work
# mount runtime.toml + targets at /work, state goes to data_dir from the config
# optional: COPY a nuclei binary + templates in for the CVE check
# COPY vendor/nuclei /usr/local/bin/nuclei
ENTRYPOINT ["leakwatch", "-c", "/work/runtime.toml"]
CMD ["runtime", "daemon"]
