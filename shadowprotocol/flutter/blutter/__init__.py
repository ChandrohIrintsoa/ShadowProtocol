"""
ShadowProtocol - Blutter-Termux Integration

Integration of blutter-termux for Dart/Flutter binary analysis.
This subpackage replaces the old Rituel D implementation.

Provides:
- BlutterRunner: High-level API for running Blutter analysis
- Dart/Flutter binary information extraction
- ASM output generation for Flutter patching

Note: Requires pyelftools and requests packages at runtime.
"""

try:
    from .blutter_engine import (
        BlutterInput,
        find_lib_files,
        extract_libs_from_apk,
        get_dart_lib_info,
        build_and_run,
        main as blutter_main,
        main2 as blutter_main2,
    )
    from .extract_dart_info import extract_dart_info
    from .dartvm_fetch_build import DartLibInfo
    _BLUTTER_AVAILABLE = True
except ImportError:
    _BLUTTER_AVAILABLE = False
    # Define stubs for when dependencies are missing
    BlutterInput = None
    find_lib_files = None
    extract_libs_from_apk = None
    get_dart_lib_info = None
    build_and_run = None
    blutter_main = None
    blutter_main2 = None
    extract_dart_info = None
    DartLibInfo = None

__all__ = [
    "BlutterRunner",
    "BlutterInput",
    "find_lib_files",
    "extract_libs_from_apk",
    "get_dart_lib_info",
    "build_and_run",
    "blutter_main",
    "blutter_main2",
    "extract_dart_info",
    "DartLibInfo",
]


class BlutterRunner:
    """High-level Blutter analysis runner integrated with ShadowProtocol.

    Provides a clean API to:
    - Accept directory path (with libapp.so + libflutter.so) or APK path
    - Accept output directory for analysis results
    - Run full Blutter analysis pipeline
    - Return structured results for downstream patching

    Requires pyelftools and requests packages for full functionality.
    """

    def __init__(self, input_path, output_dir, log_callback=None,
                 rebuild_blutter=False, no_analysis=False, ida_fcn=False):
        """Initialize BlutterRunner.

        Args:
            input_path: Path to directory containing libapp.so + libflutter.so,
                        or path to an APK file.
            output_dir: Directory where Blutter output will be written.
            log_callback: Callback function for logging (ShadowProtocol style).
            rebuild_blutter: Force rebuild the Blutter executable.
            no_analysis: Skip code analysis phase.
            ida_fcn: Generate IDA function names script.
        """
        if not _BLUTTER_AVAILABLE:
            raise ImportError(
                "Blutter dependencies not installed. "
                "Install: pip install pyelftools requests"
            )
        self.input_path = input_path
        self.output_dir = output_dir
        self.log = log_callback or (lambda msg: None)
        self.rebuild_blutter = rebuild_blutter
        self.no_analysis = no_analysis
        self.ida_fcn = ida_fcn

        self.libapp_path = None
        self.libflutter_path = None
        self.blutter_out_dir = None
        self.is_apk = False

    def _resolve_inputs(self):
        """Resolve input path to libapp.so and libflutter.so paths.

        Returns:
            True if inputs were resolved successfully.

        Raises:
            FileNotFoundError: If required files are missing.
        """
        import os

        if not os.path.exists(self.input_path):
            raise FileNotFoundError(f"Chemin introuvable: {self.input_path}")

        if self.input_path.lower().endswith('.apk'):
            self.is_apk = True
            self.log("[D] APK detecte, extraction de libapp.so et libflutter.so...")
            import tempfile
            tmp_dir = tempfile.mkdtemp(prefix='sp_blutter_')
            self.libapp_path, self.libflutter_path = extract_libs_from_apk(
                self.input_path, tmp_dir
            )
            self.log(f"[D] libapp.so: {self.libapp_path}")
            self.log(f"[D] libflutter.so: {self.libflutter_path}")
        else:
            # Directory containing libapp.so and libflutter.so
            if os.path.isdir(self.input_path):
                self.log(f"[D] Repertoire detecte: {self.input_path}")
                self.libapp_path, self.libflutter_path = find_lib_files(self.input_path)
                self.log(f"[D] libapp.so: {self.libapp_path}")
                self.log(f"[D] libflutter.so: {self.libflutter_path}")
            elif os.path.isfile(self.input_path):
                # Single file - could be libapp.so directly
                # Try to find libflutter.so in the same directory
                parent = os.path.dirname(self.input_path)
                name = os.path.basename(self.input_path).lower()

                if 'libapp' in name:
                    self.libapp_path = os.path.abspath(self.input_path)
                    flutter_candidate = os.path.join(parent, 'libflutter.so')
                    if os.path.isfile(flutter_candidate):
                        self.libflutter_path = os.path.abspath(flutter_candidate)
                    else:
                        raise FileNotFoundError(
                            f"libflutter.so non trouve dans: {parent}"
                        )
                elif 'libflutter' in name:
                    self.libflutter_path = os.path.abspath(self.input_path)
                    app_candidate = os.path.join(parent, 'libapp.so')
                    if os.path.isfile(app_candidate):
                        self.libapp_path = os.path.abspath(app_candidate)
                    else:
                        raise FileNotFoundError(
                            f"libapp.so non trouve dans: {parent}"
                        )
                else:
                    raise FileNotFoundError(
                        f"Fichier non reconnu: {self.input_path}. "
                        f"Attendu: libapp.so, libflutter.so, repertoire ou APK"
                    )
            else:
                raise FileNotFoundError(
                    f"Chemin invalide: {self.input_path}"
                )

        return True

    def run(self):
        """Execute the full Blutter analysis pipeline.

        Returns:
            Dict with analysis results:
            - success: bool
            - libapp_path: str
            - libflutter_path: str
            - output_dir: str
            - asm_dir: str (path to asm output)
            - pp_txt: str (path to pp.txt if generated)
            - dart_info: DartLibInfo
        """
        import os

        self._resolve_inputs()

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

        self.log("[D] Extraction des informations Dart/Flutter...")
        dart_info = get_dart_lib_info(self.libapp_path, self.libflutter_path)
        self.log(f"[D] Dart version: {dart_info.version}")
        self.log(f"[D] Plateforme: {dart_info.os_name} {dart_info.arch}")
        self.log(f"[D] Compressed pointers: {dart_info.has_compressed_ptrs}")

        # Create BlutterInput
        blutter_input = BlutterInput(
            libapp_path=self.libapp_path,
            dart_info=dart_info,
            outdir=self.output_dir,
            rebuild_blutter=self.rebuild_blutter,
            create_vs_sln=False,
            no_analysis=self.no_analysis,
            ida_fcn=self.ida_fcn,
        )

        self.log("[D] Execution de Blutter...")
        build_and_run(blutter_input)

        self.blutter_out_dir = self.output_dir

        # Check outputs
        asm_dir = os.path.join(self.output_dir, "asm")
        pp_txt = os.path.join(self.output_dir, "pp.txt")

        if os.path.exists(asm_dir):
            asm_count = len([f for f in os.listdir(asm_dir)
                            if f.endswith('.dart') or f.endswith('.asm')])
            self.log(f"[D] Repertoire asm genere: {asm_count} fichier(s)")
        else:
            self.log("[D] Aucun repertoire asm genere")

        if os.path.exists(pp_txt):
            self.log(f"[D] pp.txt genere: {pp_txt}")
        else:
            self.log("[D] Aucun pp.txt genere")

        self.log("[D] Analyse Blutter terminee")

        return {
            'success': True,
            'libapp_path': self.libapp_path,
            'libflutter_path': self.libflutter_path,
            'output_dir': self.output_dir,
            'asm_dir': asm_dir if os.path.exists(asm_dir) else None,
            'pp_txt': pp_txt if os.path.exists(pp_txt) else None,
            'dart_info': dart_info,
        }
