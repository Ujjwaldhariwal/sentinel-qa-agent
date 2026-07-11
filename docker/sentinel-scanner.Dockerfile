FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m pip install --upgrade pip==25.1.1 \
    && python -m pip install \
      bandit==1.8.6 \
      pip-audit==2.9.0 \
      semgrep==1.127.0

USER 65532:65532
WORKDIR /workspace/repo
