"""
Flutter Patcher Installer - Auto-install for Termux environments

Provides automatic installation of required tools:
- Termux packages (openjdk-17, python, git, cmake, etc.)
- Blutter (Flutter analysis tool)
- Radare2
- Pptool
- APKEditor

Merged from ultimate_flutter_patcher.py installer code.
"""

import os
import sys
import shutil
import subprocess
import traceback


def check_termux():
    """Check if running in Termux environment.

    Returns:
        True if Termux is detected.
    """
    return os.path.exists('/data/data/com.termux/files/usr/bin')


def install_packages():
    """Install required Termux and Python packages.

    Returns:
        True if all packages were installed successfully.
    """
    print("="*60)
    print("CHECKING REQUIRED PACKAGES")
    print("="*60)

    packages = [
        "openjdk-17", "python", "git", "cmake", "ninja",
        "build-essential", "pkg-config", "libicu", "capstone",
        "fmt", "wget", "unzip"
    ]

    pip_packages = ["requests", "pyelftools", "r2pipe"]

    try:
        print("Updating package list...")
        subprocess.run(
            ["pkg", "update", "-y"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print("Package list updated")

        for pkg in packages:
            print(f"Checking package: {pkg}...")
            result = subprocess.run(
                ["pkg", "list-installed", pkg],
                capture_output=True, text=True
            )
            if result.returncode != 0 or pkg not in result.stdout:
                print(f"  Installing: {pkg}")
                subprocess.run(
                    ["pkg", "install", "-y", pkg],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                print(f"  {pkg} installed")
            else:
                print(f"  {pkg} already installed")

        print("\nChecking Python packages...")
        for pip_pkg in pip_packages:
            try:
                __import__(pip_pkg.replace("-", "_"))
                print(f"  {pip_pkg} already installed")
            except ImportError:
                print(f"  Installing: {pip_pkg}")
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", pip_pkg],
                    check=True
                )
                print(f"  {pip_pkg} installed")

        print("\n" + "="*60)
        print("ALL PACKAGES SUCCESSFULLY CHECKED/INSTALLED")
        print("="*60)
        return True

    except Exception as e:
        print(f"Package installation error: {e}")
        return False


def install_blutter():
    """Install Blutter for Flutter analysis.

    Returns:
        True if Blutter was installed successfully.
    """
    print("\n" + "="*60)
    print("CHECKING BLUTTER")
    print("="*60)

    home = os.path.expanduser("~")
    blutter_dir = os.path.join(home, "blutter-termux")

    if os.path.exists(blutter_dir) and os.path.exists(os.path.join(blutter_dir, "blutter.py")):
        print("Blutter already installed")
        return True

    try:
        print("Downloading Blutter...")
        subprocess.run(
            ["git", "clone", "https://github.com/AbhiTheModder/blutter-termux.git", blutter_dir],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print("Blutter downloaded")

        subprocess.run(
            ["find", ".", "-type", "f", "-exec", "sed", "-i", "s/std::format/fmt::format/g", "{}", "+"],
            cwd=blutter_dir,
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print("Files updated")

        print("Blutter successfully installed and configured")
        return True

    except Exception as e:
        print(f"Blutter installation error: {e}")
        return False


def check_and_install_r2():
    """Check and install Radare2 if needed.

    Returns:
        True if Radare2 is available.
    """
    print("\n" + "="*60)
    print("CHECKING RADARE2")
    print("="*60)

    if shutil.which("r2"):
        print("Radare2 already installed")
        return True

    try:
        print("Installing Radare2...")
        subprocess.run(
            ["pkg", "install", "-y", "radare2"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        if shutil.which("r2"):
            print("Radare2 successfully installed")
            return True
        else:
            print("Radare2 installation failed")
            return False

    except Exception as e:
        print(f"Radare2 installation error: {e}")
        return False


def check_and_install_pptool():
    """Check and install Pptool if needed.

    Returns:
        True if Pptool is available.
    """
    print("\n" + "="*60)
    print("CHECKING PPTOOL")
    print("="*60)

    if shutil.which("pptool"):
        print("Pptool already installed")
        return True

    try:
        print("Downloading and compiling Pptool...")
        home = os.path.expanduser("~")
        pptool_dir = os.path.join(home, "ppfind")

        if os.path.exists(pptool_dir):
            shutil.rmtree(pptool_dir)

        subprocess.run(
            ["git", "clone", "https://github.com/Pr0214/ppfind", pptool_dir],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        subprocess.run(
            ["g++", "-std=c++11", "-o", "pptool", "pptool.cpp"],
            cwd=pptool_dir,
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(["chmod", "+x", os.path.join(pptool_dir, "pptool")], check=True)
        shutil.copy(os.path.join(pptool_dir, "pptool"), "/data/data/com.termux/files/usr/bin/")

        if shutil.which("pptool"):
            print("Pptool successfully installed")
            return True
        else:
            print("Pptool installation failed")
            return False

    except Exception as e:
        print(f"Pptool installation error: {e}")
        return False


def run_auto_installation():
    """Run full auto-installation for Termux environments.

    Returns:
        True if all tools were installed successfully.
    """
    if not check_termux():
        print("This script should only be run in Termux environment!")
        return False

    print("\n" + "="*60)
    print("FLUTTER SMALI PATCHER - AUTO INSTALLATION")
    print("="*60)
    print("All required tools will be checked and installed...")
    print("="*60 + "\n")

    try:
        if not install_packages():
            print("Package installation failed!")
            return False

        if not install_blutter():
            print("Blutter installation failed!")
            return False

        if not check_and_install_r2():
            print("Radare2 installation failed!")
            return False

        if not check_and_install_pptool():
            print("Pptool installation failed!")
            return False

        # Check APKEditor via the apk subpackage
        from ..apk.editor import ensure_apkeditor
        jar_file = ensure_apkeditor()
        if not jar_file:
            print("APKEditor installation failed!")
            return False

        print("\n" + "="*60)
        print("AUTO INSTALLATION COMPLETED!")
        print("="*60)
        print("All required tools successfully installed.")
        print("Flutter Smali Patcher is now ready to use!")
        print("="*60 + "\n")

        return True

    except Exception as e:
        print(f"Auto installation error: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return False
