"""
ShadowProtocol - Module Blutter-Termux

Integration de l'outil B(l)utter-Termux pour le reverse engineering
d'applications Flutter. Permet l'extraction et l'analyse des binaires
Dart AOT compilees.

Fonctionnalites:
- Extraction des informations Dart (version, snapshot hash, flags)
- Telechargement et compilation du Dart VM
- Execution de Blutter pour generer asm/pp.txt/objs.txt
- Support Termux avec fmt::format (au lieu de std::format)

Ce module est utilise par le Rituel D (Le Patcheur Flutter) pour
l'etape d'analyse du binaire Flutter avant le patchage.
"""

from .blutter_cli import (
    BlutterInput,
    find_lib_files,
    extract_libs_from_apk,
    find_compat_macro,
    cmake_blutter,
    get_dart_lib_info,
    build_and_run,
    main as blutter_main,
    main2 as blutter_main2,
    main_no_flutter as blutter_main_no_flutter,
)

from .extract_dart_info import extract_dart_info

__all__ = [
    "BlutterInput",
    "find_lib_files",
    "extract_libs_from_apk",
    "find_compat_macro",
    "cmake_blutter",
    "get_dart_lib_info",
    "build_and_run",
    "blutter_main",
    "blutter_main2",
    "blutter_main_no_flutter",
    "extract_dart_info",
]
