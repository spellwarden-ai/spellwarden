# The Spellwarden scanner image (spec 7.2). release.yml builds it from the wheel of the same workflow run and a
# hash-checked PyYAML wheelhouse; every pip call is --no-index, so the build cannot reach PyPI and cannot race the
# publication. The `system` stage is the only one that needs the network (Debian's git). `--network none` forces
# that mode on every RUN, the system stage's included, and the mode is part of a RUN's cache key, so the stage cannot
# be cached from an earlier build. check.yml therefore builds `--target system -t spellwarden-system` first and then
# builds the rest with --network none on top of that image (the default SYSTEM_BASE); release.yml has the network and
# passes SYSTEM_BASE=system to build the stage in the same run.
ARG SYSTEM_BASE=spellwarden-system
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS system
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --user-group --create-home --shell /usr/sbin/nologin spellwarden

FROM ${SYSTEM_BASE}
ARG VERSION
ARG WHEEL_SHA256
ARG REVISION=unknown
ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY docker/requirements.deps.txt /tmp/install/requirements.deps.txt
COPY wheelhouse/ /tmp/install/wheelhouse/
COPY dist/spellwarden-${VERSION}-py3-none-any.whl /tmp/install/
RUN set -eu; \
    test -n "${VERSION}" || { echo "the VERSION build argument is required" >&2; exit 1; }; \
    test -n "${WHEEL_SHA256}" || { echo "the WHEEL_SHA256 build argument is required" >&2; exit 1; }; \
    wheel="/tmp/install/spellwarden-${VERSION}-py3-none-any.whl"; \
    echo "${WHEEL_SHA256}  ${wheel}" | sha256sum -c -; \
    pip install --no-index --find-links /tmp/install/wheelhouse --require-hashes --no-deps -r /tmp/install/requirements.deps.txt; \
    pip install --no-index --no-deps "${wheel}"; \
    installed="$(python -c 'import importlib.metadata as m; print(m.version("spellwarden"))')"; \
    test "${installed}" = "${VERSION}" || { echo "installed ${installed}, expected ${VERSION}" >&2; exit 1; }; \
    rm -rf /tmp/install
LABEL org.opencontainers.image.source="https://github.com/spellwarden-ai/spellwarden" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.title="Spellwarden scanner"
USER spellwarden
WORKDIR /src
ENTRYPOINT ["python", "-I", "-m", "spellwarden_cli"]
CMD ["scan"]
