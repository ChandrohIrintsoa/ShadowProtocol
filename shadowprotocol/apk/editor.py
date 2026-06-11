"""
APK Editor - APKEditor JAR operations

Provides:
- APKEditor JAR discovery and download
- APK merge (split APKs -> single APK)
- Split folder cleanup

Merged from flutter_patcher.py and ultimate_flutter_patcher.py,
deduplicating all shared functionality.
"""

import os
import json
import shutil
import subprocess
import urllib.request

def find_apkeditor_jar():
    """Find APKEditor JAR in the current directory.

    Returns:
        Filename of the JAR if found, None otherwise.
    """
    for f in os.listdir('.'):
        if f.lower().endswith('.jar') and "apkeditor" in f.lower():
            return f
    # Fallback: check for APKEditor*.jar pattern in current dir
    for f in os.listdir('.'):
        if f.lower().endswith('.jar') and (f.startswith('APKEditor') or 'apkeditor' in f.lower()):
            return f
    return None

def get_latest_apkeditor_url():
    """Get the latest APKEditor download URL from GitHub.

    Returns:
        Tuple of (filename, download_url).
    """
    api_url = "https://api.github.com/repos/REAndroid/APKEditor/releases/latest"
    try:
        with urllib.request.urlopen(api_url) as resp:
            data = json.load(resp)
        for asset in data.get("assets", []):
            if asset["name"].endswith(".jar") and "apkeditor" in asset["name"].lower():
                return asset["name"], asset["browser_download_url"]
    except Exception:
        pass
    return ("APKEditor.jar",
            "https://github.com/REAndroid/APKEditor/releases/latest/download/APKEditor.jar")

def download_file(url, outname):
    """Download a file from URL.

    Args:
        url: URL to download from.
        outname: Output filename.
    """
    print(f"Downloading: {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'flutter_patcher/1.0'})
    with urllib.request.urlopen(req) as resp, open(outname, 'wb') as f:
        shutil.copyfileobj(resp, f)
    print("Download completed.")

def ensure_apkeditor():
    """Ensure APKEditor JAR is available, downloading if necessary.

    Returns:
        Filename of the APKEditor JAR.
    """
    jar = find_apkeditor_jar()
    if jar:
        print(f"APKEditor jar found: {jar}")
        return jar
    name, url = get_latest_apkeditor_url()
    print("APKEditor jar not found. Downloading latest version...")
    download_file(url, name)
    return name

def has_java():
    """Check if Java is available on the system.

    Returns:
        True if Java is found.
    """
    return shutil.which("java") is not None

def run_merge(jarfile, apks, apk):
    """Merge split APKs into a single APK using APKEditor.

    Args:
        jarfile: Path to APKEditor JAR.
        apks: Path to input .apks file.
        apk: Path to output .apk file.

    Returns:
        Subprocess return code.
    """
    cmd = ["java", "-jar", jarfile, "m", "-i", apks, "-o", apk]
    print("Merging split APKs...")
    return subprocess.call(cmd)

def auto_clean_splitfolder(base_name):
    """Clean up split APK folder after merge.

    Args:
        base_name: Base name of the .apks file (without extension).
    """
    folder = os.path.abspath(base_name)
    if os.path.isdir(folder):
        try:
            shutil.rmtree(folder)
            print(f"Split folder auto-cleaned: {folder}")
        except Exception as e:
            print(f"Warning: {folder} could not be removed: {e}")
