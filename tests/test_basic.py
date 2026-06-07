"""ShadowProtocol Test Suite - Basic Tests"""

import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shadowprotocol.target_selector import TargetSelector, TargetValidator
from shadowprotocol.validator import DependencyValidator, CodeValidator
from shadowprotocol.config import Config


class TestTargetSelector:
    """Tests for TargetSelector path validation."""

    def test_valid_elf_binary(self):
        """Validate a valid ELF binary file."""
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
            f.flush()
            try:
                selector = TargetSelector()
                result = selector.validate_manual_path(f.name)
                assert result is not None, "Valid ELF should be accepted"
                assert result == os.path.abspath(f.name)
            finally:
                os.unlink(f.name)

    def test_rejects_non_elf(self):
        """Reject a non-ELF file."""
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
            f.write(b'not an ELF file' + b'\x00' * 100)
            f.flush()
            try:
                selector = TargetSelector()
                result = selector.validate_manual_path(f.name)
                assert result is None, "Non-ELF should be rejected"
            finally:
                os.unlink(f.name)

    def test_rejects_symlink(self):
        """Reject a symlink even if it points to a valid ELF."""
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
            f.flush()
            link_path = f.name + ".link"
            try:
                os.symlink(f.name, link_path)
                selector = TargetSelector()
                result = selector.validate_manual_path(link_path)
                assert result is None, "Symlink should be rejected"
            finally:
                if os.path.exists(link_path):
                    os.unlink(link_path)
                os.unlink(f.name)

    def test_rejects_directory(self):
        """Reject a directory path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            selector = TargetSelector()
            result = selector.validate_manual_path(tmpdir)
            assert result is None, "Directory should be rejected"

    def test_rejects_empty_path(self):
        """Reject empty path string."""
        selector = TargetSelector()
        assert selector.validate_manual_path("") is None
        assert selector.validate_manual_path("   ") is None

    def test_rejects_nonexistent(self):
        """Reject non-existent file path."""
        selector = TargetSelector()
        result = selector.validate_manual_path("/nonexistent/path/file.so")
        assert result is None


class TestTargetValidator:
    """Tests for TargetValidator static methods."""

    def test_is_valid_so_with_elf(self):
        """Return True for valid ELF magic bytes."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'\x7fELF' + b'\x00' * 50)
            f.flush()
            try:
                assert TargetValidator.is_valid_so(f.name) is True
            finally:
                os.unlink(f.name)

    def test_is_valid_so_with_non_elf(self):
        """Return False for non-ELF files."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'PE\x00\x00' + b'\x00' * 50)
            f.flush()
            try:
                assert TargetValidator.is_valid_so(f.name) is False
            finally:
                os.unlink(f.name)

    def test_is_valid_so_nonexistent(self):
        """Return False for non-existent files."""
        assert TargetValidator.is_valid_so("/nonexistent/file.so") is False

    def test_get_arch_arm64(self):
        """Detect ARM64 architecture."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'\x7fELF' + b'\x00' * 14 + b'\xb7\x00')
            f.flush()
            try:
                arch = TargetValidator.get_arch(f.name)
                assert arch == "ARM64"
            finally:
                os.unlink(f.name)


class TestDependencyValidator:
    """Tests for DependencyValidator."""

    def test_check_python_version(self):
        """Python version check should always pass in tests."""
        ok, msg = DependencyValidator.check_python_version()
        assert ok is True
        assert "Python" in msg

    def test_validate_all_returns_tuple(self):
        """validate_all returns (bool, list)."""
        ok, messages = DependencyValidator.validate_all()
        assert isinstance(ok, bool)
        assert isinstance(messages, list)
        assert len(messages) >= 2  # At least Python + r2 checks


class TestCodeValidator:
    """Tests for CodeValidator static methods."""

    def test_find_unused_imports(self):
        """Detect unused imports in Python code."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import os\nimport sys\n\nprint('hello')\n")
            f.flush()
            try:
                unused = CodeValidator.find_unused_imports(f.name)
                # 'os' and 'sys' are unused
                assert 'os' in unused or 'sys' in unused
            finally:
                os.unlink(f.name)

    def test_find_unused_imports_invalid_file(self):
        """Return empty list for invalid file."""
        result = CodeValidator.find_unused_imports("/nonexistent/file.py")
        assert result == []


class TestConfig:
    """Tests for Config class."""

    def test_get_default(self):
        """Config.get returns default value."""
        result = Config.get('radare2_timeout')
        assert result == 30

    def test_get_unknown_key(self):
        """Config.get returns None for unknown keys."""
        result = Config.get('nonexistent_key')
        assert result is None

    def test_get_with_custom_default(self):
        """Config.get uses provided default for unknown keys."""
        result = Config.get('nonexistent_key', default='fallback')
        assert result == 'fallback'

    def test_init_creates_dirs(self):
        """Config.init creates default directories."""
        Config.init()
        # Should not raise an exception


if __name__ == "__main__":
    # Simple test runner for environments without pytest
    import traceback

    test_classes = [
        TestTargetSelector,
        TestTargetValidator,
        TestDependencyValidator,
        TestCodeValidator,
        TestConfig,
    ]

    total = 0
    passed = 0
    failed = 0

    for test_class in test_classes:
        instance = test_class()
        for method_name in dir(instance):
            if method_name.startswith('test_'):
                total += 1
                try:
                    getattr(instance, method_name)()
                    passed += 1
                    print(f"  PASS: {test_class.__name__}.{method_name}")
                except Exception as e:
                    failed += 1
                    print(f"  FAIL: {test_class.__name__}.{method_name}: {e}")
                    traceback.print_exc()

    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)
