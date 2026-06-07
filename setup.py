"""
ShadowProtocol v3.0 Enhanced - Setup Configuration

Install with:
    pip install .

After installation, run:
    shadowprotocol          # Interactive mode
    shadowprotocol A        # Run MODE A
    shadowprotocol B        # Run MODE B
    shadowprotocol C        # Run MODE C
    shadowprotocol D        # Run MODE D (Flutter Patcher)
    shadowprotocol E        # Run MODE E (Find Functions)
    shadowprotocol F        # Run MODE F (Manifest Patcher)
"""

from setuptools import setup, find_packages

# Read long description from README.md, fallback to short description
try:
    with open('README.md', 'r', encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = 'ShadowProtocol v3.0 - Binary Patcher with Radare2 Integration + Flutter Patcher + TUI'

setup(
    name='shadowprotocol',
    version='3.0.0',
    description='ShadowProtocol v3.0 - Binary Patcher with Radare2 Integration + Flutter Patcher + TUI',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='ShadowProtocol Enhanced Team',
    author_email='team@shadowprotocol.dev',
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
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Operating System :: MacOS',
        'Environment :: Console',
        'Topic :: Utilities',
    ],
    keywords='radare2 binary patcher reverse-engineering flutter apk',
)
