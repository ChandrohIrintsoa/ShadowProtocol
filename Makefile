# ShadowProtocol v4.0 - Makefile

.PHONY: help install dev-install run rituel-a rituel-b rituel-c rituel-d rituel-e rituel-f check validate clean test

help:
	@echo "ShadowProtocol v4.0 - Le Grimoire de Transmutation Binaire"
	@echo ""
	@echo "  make install     - Installer le paquet"
	@echo "  make dev-install - Installer en mode developpement"
	@echo "  make run         - Lancer le mode interactif"
	@echo "  make rituel-a    - Rituel A - L'Invocation Precise"
	@echo "  make rituel-b    - Rituel B - Le Balayage d'Ame"
	@echo "  make rituel-c    - Rituel C - La Connexion Directe"
	@echo "  make rituel-d    - Rituel D - Le Patcheur Flutter"
	@echo "  make rituel-e    - Rituel E - La Quete des Fonctions"
	@echo "  make rituel-f    - Rituel F - Le Patcheur de Manifeste"
	@echo "  make check       - Verifier les dependances"
	@echo "  make validate    - Valider le projet"
	@echo "  make clean       - Nettoyer les fichiers temporaires"
	@echo "  make test        - Verifications syntaxiques"

install:
	@echo "Installation de ShadowProtocol v4.0..."
	pip install .
	@echo "Termine! Lancez 'shadowprotocol' pour demarrer."

dev-install:
	@echo "Installation en mode developpement..."
	pip install -e .
	@echo "Termine!"

run:
	@echo "Ouverture du Grimoire ShadowProtocol v4.0..."
	python3 -m shadowprotocol

rituel-a:
	@echo "Rituel A : L'Invocation Precise..."
	python3 -m shadowprotocol A

rituel-b:
	@echo "Rituel B : Le Balayage d'Ame..."
	python3 -m shadowprotocol B

rituel-c:
	@echo "Rituel C : La Connexion Directe..."
	python3 -m shadowprotocol C

rituel-d:
	@echo "Rituel D : Le Patcheur Flutter..."
	python3 -m shadowprotocol D

rituel-e:
	@echo "Rituel E : La Quete des Fonctions..."
	python3 -m shadowprotocol E

rituel-f:
	@echo "Rituel F : Le Patcheur de Manifeste..."
	python3 -m shadowprotocol F

check:
	@echo "Verification des dependances..."
	python3 -m shadowprotocol --check

validate:
	@echo "Validation du projet..."
	python3 -m py_compile shadowprotocol/*.py
	python3 -m py_compile shadowprotocol/flutter/*.py
	python3 -m py_compile shadowprotocol/apk/*.py
	python3 -m shadowprotocol.validator
	@echo "Validation terminee!"

clean:
	@echo "Nettoyage des fichiers temporaires..."
	@rm -rf build/ dist/ *.egg-info __pycache__
	@find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -delete 2>/dev/null || true
	@rm -rf logs/ results/
	@echo "Nettoyage termine!"

test:
	@echo "Verifications syntaxiques..."
	python3 -m py_compile shadowprotocol/*.py
	python3 -m py_compile shadowprotocol/flutter/*.py
	python3 -m py_compile shadowprotocol/apk/*.py
	@echo "Tous les fichiers sont valides!"

uninstall:
	@echo "Desinstallation de ShadowProtocol..."
	pip uninstall shadowprotocol -y
	@echo "Termine!"
