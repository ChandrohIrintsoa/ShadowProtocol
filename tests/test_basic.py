"""ShadowProtocol Test Suite - Basic Tests"""

import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shadowprotocol.target import TargetSelector, TargetValidator
from shadowprotocol.validator import DependencyValidator, CodeValidator
from shadowprotocol.config import Config
from shadowprotocol.keyword_analyzer import KeywordDictionary, BinaryAnalyzer
from shadowprotocol.file_manager import FileManager


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
        assert len(messages) >= 2

    def test_check_r2pipe_actually_checks(self):
        """check_r2pipe should actually verify the import."""
        ok, msg = DependencyValidator.check_r2pipe()
        assert isinstance(ok, bool)
        # The result depends on whether r2pipe is installed
        if ok:
            assert "OK" in msg
        else:
            assert "missing" in msg or "not found" in msg


class TestCodeValidator:
    """Tests for CodeValidator static methods."""

    def test_find_unused_imports(self):
        """Detect unused imports in Python code."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import os\nimport sys\n\nprint('hello')\n")
            f.flush()
            try:
                unused = CodeValidator.find_unused_imports(f.name)
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
        assert result == 60

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


class TestKeywordDictionary:
    """Tests for KeywordDictionary."""

    def test_load_from_comma_separated_file(self):
        """Load keywords from comma-separated .txt file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('"mot1", "mot2", "mot3"')
            f.flush()
            try:
                kd = KeywordDictionary(f.name)
                assert kd.is_loaded()
                assert len(kd) == 3
                assert "mot1" in kd.get_keywords()
                assert "mot2" in kd.get_keywords()
                assert "mot3" in kd.get_keywords()
            finally:
                os.unlink(f.name)

    def test_load_from_line_separated_file(self):
        """Load keywords from one-per-line .txt file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("keyword1\nkeyword2\nkeyword3\n")
            f.flush()
            try:
                kd = KeywordDictionary(f.name)
                assert kd.is_loaded()
                assert len(kd) == 3
            finally:
                os.unlink(f.name)

    def test_add_keyword_manually(self):
        """Add keyword manually."""
        kd = KeywordDictionary()
        kd.add_keyword("test_keyword")
        assert kd.is_loaded()
        assert "test_keyword" in kd.get_keywords()

    def test_add_keywords_from_input(self):
        """Add keywords from user input string."""
        kd = KeywordDictionary()
        added = kd.add_keywords_from_input('"mot1", "mot2"')
        assert added == 2
        assert "mot1" in kd.get_keywords()
        assert "mot2" in kd.get_keywords()

    def test_empty_dictionary(self):
        """Empty dictionary should not be loaded."""
        kd = KeywordDictionary()
        assert not kd.is_loaded()
        assert len(kd) == 0


class TestBinaryAnalyzer:
    """Tests for BinaryAnalyzer."""

    def test_load_binary(self):
        """Load a binary file."""
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
            f.flush()
            try:
                analyzer = BinaryAnalyzer(f.name)
                assert analyzer.is_loaded()
            finally:
                os.unlink(f.name)

    def test_find_keyword_offsets(self):
        """Find keyword offsets in binary."""
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b'\x00' * 64 + b'isPro' + b'\x00' * 50)
            f.flush()
            try:
                analyzer = BinaryAnalyzer(f.name)
                offsets = analyzer.find_keyword_offsets("isPro")
                assert len(offsets) >= 1
                assert 64 in offsets
            finally:
                os.unlink(f.name)

    def test_validate_offset_safety(self):
        """Validate offset safety - reject header region."""
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
            f.write(b'\x7fELF' + b'\x00' * 200)
            f.flush()
            try:
                analyzer = BinaryAnalyzer(f.name)
                # Offset in header should be unsafe
                assert not analyzer._validate_offset_safety(10)
                # Offset after header should be safe
                assert analyzer._validate_offset_safety(100)
            finally:
                os.unlink(f.name)

    def test_get_binary_info(self):
        """Get binary info."""
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
            f.flush()
            try:
                analyzer = BinaryAnalyzer(f.name)
                info = analyzer.get_binary_info()
                assert info['is_elf'] is True
                assert info['size'] == 104
            finally:
                os.unlink(f.name)


class TestFileManager:
    """Tests for FileManager."""

    def test_create_skull_folder(self):
        """Create skull folder."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "test.so")
            with open(target, 'w') as f:
                f.write("test")
            fm = FileManager(target)
            assert fm.create_skull_folder()
            assert fm.skull_exists()

    def test_move_to_skull(self):
        """Move file to skull folder."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "test.so")
            with open(target, 'w') as f:
                f.write("test content")
            fm = FileManager(target)
            result = fm.move_to_skull(target)
            assert result is not None
            assert os.path.exists(result)
            assert not os.path.exists(target)

    def test_copy_to_skull(self):
        """Copy file to skull folder (keep original)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "test.so")
            with open(target, 'w') as f:
                f.write("test content")
            fm = FileManager(target)
            result = fm.copy_to_skull(target)
            assert result is not None
            assert os.path.exists(result)
            assert os.path.exists(target)

    def test_find_targets_in_path(self):
        """Find targets in a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            so_file = os.path.join(tmpdir, "libtest.so")
            with open(so_file, 'w') as f:
                f.write("test")
            targets = FileManager.find_targets_in_path(tmpdir)
            assert len(targets) >= 1


if __name__ == "__main__":
    import traceback

    test_classes = [
        TestTargetSelector,
        TestTargetValidator,
        TestDependencyValidator,
        TestCodeValidator,
        TestConfig,
        TestKeywordDictionary,
        TestBinaryAnalyzer,
        TestFileManager,
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
