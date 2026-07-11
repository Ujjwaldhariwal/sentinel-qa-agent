PYTHON ?= python3
SCANNER_IMAGE ?= sentinel-qa-scanner:latest

.PHONY: install scanner-image test compile smoke self-scan clean

install:
	$(PYTHON) -m pip install -e .

scanner-image:
	docker build -f docker/sentinel-scanner.Dockerfile -t $(SCANNER_IMAGE) .

compile:
	$(PYTHON) -m py_compile *.py tests/*.py

test: compile
	$(PYTHON) -m unittest discover -s tests -v

smoke:
	tmp_dir=$$(mktemp -d); \
	printf "[project]\nname='tiny'\nversion='0.1.0'\n" > "$$tmp_dir/pyproject.toml"; \
	printf "print('ok')\n" > "$$tmp_dir/app.py"; \
	$(PYTHON) sentinel_qa.py "$$tmp_dir" --output-dir "$$tmp_dir/report" --workers 1 --timeout 30 --max-files 100; \
	test -f "$$tmp_dir/report/report.md"; \
	test -f "$$tmp_dir/report/report.json"

self-scan:
	$(PYTHON) sentinel_qa.py . --output-dir ./reports/self-scan --workers 1 --max-scan-seconds 180

clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache .sentinel-sandbox-out
