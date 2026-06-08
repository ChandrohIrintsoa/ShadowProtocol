"""
Flutter Manifest Patcher - APK Manifest modification

Provides:
- License check receiver removal
- extractNativeLibs attribute patching
- APK decompile/patch/rebuild workflow

Merged from ultimate_flutter_patcher.py manifest patching code.
"""

import os
import re
import time
import shutil
import subprocess

MANIFEST_PATCHES = [
    (re.compile(r'<[^>]*\b(?:com\.pairip\.licensecheck|android\.vending\.CHECK_LICENSE)\b[^>]*/>'),
     '<!-- License check disabled -->', "CHECK_LICENSE"),
    ("extractNativeLibs", lambda content: content.replace('android:extractNativeLibs="false"', ''))
]

def safe_regex_operation(pattern, replacement, content, description, file_path=""):
    """Safely apply a regex replacement to content.

    Args:
        pattern: Compiled regex pattern or string.
        replacement: Replacement string.
        content: The content to modify.
        description: Description of the operation for error reporting.
        file_path: Optional file path for error reporting.

    Returns:
        Tuple of (success, new_content, error_message).
    """
    try:
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        new_content = pattern.sub(replacement, content)
        if new_content != content:
            return True, new_content, None
        else:
            return True, content, f"Pattern not matched: {description}"
    except Exception as e:
        error_message = f"Regex error [{description}]: {str(e)}"
        if file_path:
            error_message += f" - File: {os.path.basename(file_path)}"
        return False, content, error_message

def safe_function_operation(func, content, description, file_path=""):
    """Safely apply a function transformation to content.

    Args:
        func: Transformation function.
        content: The content to modify.
        description: Description of the operation for error reporting.
        file_path: Optional file path for error reporting.

    Returns:
        Tuple of (success, new_content, error_message).
    """
    try:
        new_content = func(content)
        return True, new_content, None
    except Exception as e:
        error_message = f"Function error [{description}]: {str(e)}"
        if file_path:
            error_message += f" - File: {os.path.basename(file_path)}"
        return False, content, error_message

def _run_command(command, verbose=True, exit_on_error=True):
    """Run a shell command.

    Args:
        command: Shell command string.
        verbose: Print errors on failure.
        exit_on_error: If True, raise RuntimeError on command failure.

    Returns:
        Command stdout, or empty string on failure (when exit_on_error=False).

    Raises:
        RuntimeError: If exit_on_error=True and the command fails.
    """
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            if verbose:
                print(f"Command failed: {command}\n{result.stderr}")
            if exit_on_error:
                raise RuntimeError(f"Command failed with code {result.returncode}: {command}")
            return ""
        return result.stdout.strip()
    except RuntimeError:
        raise  # Re-raise RuntimeError from exit_on_error
    except Exception as e:
        if verbose:
            print(f"Command error: {command}\n{str(e)}")
        if exit_on_error:
            raise RuntimeError(f"Command error: {str(e)}")
        return ""

def _decompile_apk(apk_path, output_dir, jar_file):
    """Decompile APK using APKEditor.

    Args:
        apk_path: Path to the APK file.
        output_dir: Output directory for decompiled files.
        jar_file: Path to APKEditor jar.

    Returns:
        True if decompilation succeeded.
    """
    print("Decompiling APK...")
    cmd = f'java -jar "{jar_file}" d -i "{apk_path}" -o "{output_dir}"'
    try:
        _run_command(cmd, verbose=False, exit_on_error=False)
    except RuntimeError:
        return False
    return os.path.exists(output_dir)

def _build_apk(source_dir, output_apk, jar_file):
    """Build APK from decompiled directory using APKEditor.

    Args:
        source_dir: Directory containing decompiled APK.
        output_apk: Output APK path.
        jar_file: Path to APKEditor jar.

    Returns:
        True if build succeeded.
    """
    print("Building APK...")
    cmd = f'java -jar "{jar_file}" b -i "{source_dir}" -o "{output_apk}"'
    try:
        _run_command(cmd, verbose=False, exit_on_error=False)
    except RuntimeError:
        return False
    if os.path.exists(output_apk):
        file_size = os.path.getsize(output_apk) / (1024 * 1024)
        print(f"APK successfully built ({file_size:.2f} MB)")
        return True
    return False

def patch_android_manifest(decompile_dir):
    """Patch AndroidManifest.xml in a decompiled APK directory.

    Applies all MANIFEST_PATCHES:
    - Remove license check receivers
    - Fix extractNativeLibs attribute

    Args:
        decompile_dir: Path to the decompiled APK directory.

    Returns:
        True if patching succeeded or no changes needed.
    """
    print("Patching AndroidManifest.xml...")
    manifest_path = os.path.join(decompile_dir, 'AndroidManifest.xml')
    if not os.path.exists(manifest_path):
        print("AndroidManifest.xml not found")
        return False

    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content

        if not MANIFEST_PATCHES:
            print("No manifest patches defined")
            return True

        for patch in MANIFEST_PATCHES:
            if len(patch) == 3:
                pattern, replacement, description = patch
                success, new_content, error_msg = safe_regex_operation(
                    pattern, replacement, content, description, manifest_path
                )
                if not success:
                    print(f"Manifest patch error: {error_msg}")
                    continue
                if new_content != content:
                    content = new_content
                    print(f"Applied (regex): {description}")

            elif len(patch) == 2:
                description, patch_func = patch
                success, new_content, error_msg = safe_function_operation(
                    patch_func, content, description, manifest_path
                )
                if not success:
                    print(f"Manifest patch error: {error_msg}")
                    continue
                if new_content != content:
                    content = new_content
                    print(f"Applied (function): {description}")

        if content != original_content:
            with open(manifest_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print("AndroidManifest.xml successfully patched")
            return True
        else:
            print("No changes made to AndroidManifest.xml")
            return True

    except Exception as e:
        print(f"Failed to patch AndroidManifest.xml: {e}")
        return False

def process_manifest_patcher(apk_path, jar_file):
    """Full manifest patcher workflow: decompile -> patch -> rebuild.

    Args:
        apk_path: Path to the APK file.
        jar_file: Path to APKEditor jar.

    Returns:
        True if manifest patching succeeded.
    """
    if not os.path.exists(apk_path):
        print(f"APK file not found: {apk_path}")
        return False

    original_dir = os.getcwd()
    apk_abs_path = os.path.abspath(apk_path)
    jar_abs_path = os.path.join(original_dir, jar_file) if not os.path.isabs(jar_file) else jar_file

    base_name = os.path.splitext(os.path.basename(apk_path))[0]
    output_apk = f"{base_name}-patched.apk"
    output_abs_path = os.path.join(original_dir, output_apk)

    work_dir = os.path.expanduser("~/apk_patch_work")
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir, ignore_errors=True)
    os.makedirs(work_dir, exist_ok=True)

    try:
        os.chdir(work_dir)
        print("Copying files to working directory...")
        shutil.copy2(apk_abs_path, "input.apk")
        if os.path.exists(jar_abs_path):
            shutil.copy2(jar_abs_path, jar_file)

        decompile_dir = "decompiled_app"
        print("Step 1/3: Decompiling APK")
        start_time = time.time()
        if not _decompile_apk("input.apk", decompile_dir, jar_file):
            return False
        print(f"Decompile completed in {time.time() - start_time:.1f} seconds")

        print("Step 2/3: Patching AndroidManifest.xml")
        start_time = time.time()
        if not patch_android_manifest(decompile_dir):
            print("Failed to patch AndroidManifest.xml")
            return False
        print(f"AndroidManifest.xml patched in {time.time() - start_time:.1f} seconds")

        print("Step 3/3: Building patched APK")
        start_time = time.time()
        if not _build_apk(decompile_dir, "output.apk", jar_file):
            return False
        print(f"Building completed in {time.time() - start_time:.1f} seconds")

        if os.path.exists("output.apk"):
            shutil.move("output.apk", output_abs_path)
            file_size = os.path.getsize(output_abs_path) / (1024 * 1024)
            print(f"Final APK: {output_apk} ({file_size:.2f} MB)")

            if os.path.exists(apk_abs_path):
                os.remove(apk_abs_path)
                print(f"Deleted previous APK: {os.path.basename(apk_abs_path)}")

            return True
        else:
            print("Output APK not found")
            return False

    except Exception as e:
        print(f"Processing error: {e}")
        return False
    finally:
        os.chdir(original_dir)
        if os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)
