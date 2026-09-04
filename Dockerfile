# ---- build ----
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY cryptonex ./cryptonex
RUN pip install --no-cache-dir build hatchling && python -m build --wheel

# ---- runtime ----
FROM python:3.12-slim
LABEL org.opencontainers.image.title="CRYPTONEX" \
      org.opencontainers.image.description="Cryptographic discovery & post-quantum risk analysis"
RUN useradd -m -u 65532 cryptonex
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl "streamlit>=1.30" "pandas>=2.0" "lief>=0.14" && rm /tmp/*.whl
COPY .streamlit /home/cryptonex/.streamlit
USER 65532
WORKDIR /scan
ENTRYPOINT ["cryptonex"]
CMD ["--help"]
