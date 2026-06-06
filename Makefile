# ShadowProtocol v3.0 - Makefile

.PHONY: help install dev-install run clean test validate mode-a mode-b mode-c mode-d mode-e mode-f

help:
	@echo "ShadowProtocol v3.0 - Available commands:"
	@echo "  make install       - Install package"
	@echo "  make dev-install   - Install in development mode"
	@echo "  make run           - Run interactive mode"
	@echo "  make mode-a        - Run MODE A directly"
	@echo "  make mode-b        - Run MODE B directly"
	@echo "  make mode-c        - Run MODE C directly"
	@echo "  make mode-d        - Run MODE D (Flutter Patcher) directly"
	@echo "  make mode-e        - Run MODE E (Find Functions) directly"
	@echo "  make mode-f        - Run MODE F (Manifest Patcher) directly"
	@echo "  make validate      - Validate project"
	@echo "  make clean         - Clean temporary files"
	@echo "  make test          - Run syntax checks"

install:
	@echo "Installing ShadowProtocol v3.0..."
	pip install .
	@echo "Done! Run 'shadowprotocol' to start."

dev-install:
	@echo "Installing in development mode..."
	pip install -e .
	@echo "Done!"

run:
	@echo "Starting ShadowProtocol v3.0 (Interactive)..."
	python3 -m shadowprotocol

mode-a:
	@echo "Starting MODE A..."
	python3 -m shadowprotocol A

mode-b:
	@echo "Starting MODE B..."
	python3 -m shadowprotocol B

mode-c:
	@echo "Starting MODE C..."
	python3 -m shadowprotocol C

mode-d:
	@echo "Starting MODE D (Flutter Patcher)..."
	python3 -m shadowprotocol D

mode-e:
	@echo "Starting MODE E (Find Functions)..."
	python3 -m shadowprotocol E

mode-f:
	@echo "Starting MODE F (Manifest Patcher)..."
	python3 -m shadowprotocol F

validate:
	@echo "Validating project..."
	python3 -m py_compile shadowprotocol/*.py
	python3 -m py_compile shadowprotocol/flutter/*.py
	python3 -m py_compile shadowprotocol/apk/*.py
	python3 -m shadowprotocol.validator
	@echo "Validation complete!"

clean:
	@echo "Cleaning temporary files..."
	@rm -rf build/ dist/ *.egg-info __pycache__
	@find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -delete 2>/dev/null || true
	@echo "Cleanup complete!"

test:
	@echo "Running syntax checks..."
	python3 -m py_compile shadowprotocol/*.py
	python3 -m py_compile shadowprotocol/flutter/*.py
	python3 -m py_compile shadowprotocol/apk/*.py
	@echo "All files valid!"

uninstall:
	@echo "Uninstalling ShadowProtocol..."
	pip uninstall shadowprotocol -y
	@echo "Done!"
