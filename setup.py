"""
ShadowProtocol v4.0 - Le Grimoire de Transmutation Binaire

Installation:
    pip install .

Utilisation:
    shadowprotocol          # Mode interactif
    shadowprotocol A        # Rituel A - L'Invocation Precise
    shadowprotocol B        # Rituel B - Le Balayage d'Ame
    shadowprotocol C        # Rituel C - La Connexion Directe
    shadowprotocol D        # Rituel D - Le Patcheur Flutter
    shadowprotocol E        # Rituel E - La Quete des Fonctions
    shadowprotocol F        # Rituel F - Le Patcheur de Manifeste
    shadowprotocol --check  # Verifier les dependances
"""

from setuptools import setup, find_packages

# Read long description from README.md, fallback to short description
try:
    with open('README.md', 'r', encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = 'ShadowProtocol v4.0 - Grimoire de Transmutation Binaire via Radare2 + Flutter Patcher'

setup(
    name='shadowprotocol',
    version='4.0.0',
    description='ShadowProtocol v4.0 - Grimoire de Transmutation Binaire via Radare2 + Flutter Patcher',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='ShadowProtocol Team',
    license='MIT',
    packages=find_packages(),
    python_requires='>=3.7',
    install_requires=[
        'r2pipe>=1.6.0',
        'requests>=2.28.0',
        'pyelftools>=0.29',
    ],
    entry_points={
        'console_scripts': [
            'shadowprotocol=shadowprotocol.main:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Operating System :: MacOS',
        'Environment :: Console',
        'Topic :: Security',
        'Topic :: Software Development :: Disassemblers',
    ],
    keywords='radare2 binary patcher reverse-engineering flutter apk android arm64 r2pipe',
)
