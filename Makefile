.PHONY: help dev test scan ui docker docker-scan clean
VENV ?= .venv
PY   := $(VENV)/bin/python
DIR  ?= tests/fixtures/vulnerable-repo
OUT  ?= ecdat-out

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

dev: ## create venv and install (editable, with dev extras)
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -U pip
	$(VENV)/bin/pip install -q -e ".[dev]"

test: ## run the test suite
	$(PY) -m pytest -q

scan: ## scan $(DIR) -> $(OUT)
	$(VENV)/bin/ecdat scan $(DIR) --out $(OUT)

ui: ## open the local console on the last scan
	$(VENV)/bin/ecdat serve --result $(OUT)/result.json

docker: ## build the image
	docker build -t ecdat:local .

docker-scan: ## run a scan inside the container ( DIR=path/to/your/repo )
	mkdir -p "$(OUT)"
	docker run --rm --user "$$(id -u):$$(id -g)" \
	  -v "$(abspath $(DIR))":/scan:ro -v "$(abspath $(OUT))":/out \
	  ecdat:local scan /scan --out /out

clean:
	rm -rf $(OUT) dist build *.egg-info .pytest_cache
