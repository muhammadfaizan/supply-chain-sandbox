# Sandbox image for installing and testing untrusted packages.
# Runtime isolation (network, capabilities, read-only root) is applied by
# scripts/run_sandbox.sh at `docker run` time, not baked into the image.
FROM python:3.13-slim-bookworm

RUN groupadd --gid 10001 sandbox \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin sandbox \
 && pip install --no-cache-dir "setuptools==75.8.0" "wheel==0.45.1"

# Honeytoken: a fake credential file. If anything reads it, the monitor logs it.
RUN printf 'FAKE_API_KEY=honeytoken-do-not-use\n' > /home/sandbox/.env \
 && chown 10001:10001 /home/sandbox/.env \
 && chmod 600 /home/sandbox/.env

COPY monitor/sitecustomize.py /opt/monitor/sitecustomize.py
COPY scripts/sandbox-install.sh /usr/local/bin/sandbox-install
RUN chmod 755 /usr/local/bin/sandbox-install

ENV PYTHONPATH=/opt/monitor:/work/site \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SANDBOX_EVENT_LOG=/tmp/events.jsonl

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/sandbox-install"]
