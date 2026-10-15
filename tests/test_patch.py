import sys
import pytest

import modern_httplib2
from modern_httplib2 import is_patched, patch, unpatch


def test_direct_modern_httplib2_import():
    assert hasattr(modern_httplib2, "Http")
    assert hasattr(modern_httplib2, "Response")
    assert hasattr(modern_httplib2, "debug_print")
    assert hasattr(modern_httplib2, "error")
    assert hasattr(modern_httplib2, "certs")
    assert hasattr(modern_httplib2, "iri2uri")


def test_is_patched():
    assert is_patched()
    import httplib2
    assert httplib2 is modern_httplib2


def test_submodules_patched():
    import httplib2.error
    import httplib2.certs
    import httplib2.iri2uri
    assert httplib2.error is modern_httplib2.error
    assert httplib2.certs is modern_httplib2.certs
    assert httplib2.iri2uri is modern_httplib2.iri2uri


def test_unpatch_and_repatch():
    assert is_patched()
    unpatch()
    assert not is_patched()
    assert "httplib2" not in sys.modules

    patch()
    assert is_patched()
    import httplib2
    assert httplib2 is modern_httplib2


def test_google_libraries_interop():
    try:
        import google_auth_httplib2
        import googleapiclient.discovery
    except ImportError:
        pytest.skip("google libraries not installed in this environment")

    assert is_patched()
    # Ensure google_auth_httplib2 sees modern_httplib2
    assert sys.modules["httplib2"] is modern_httplib2
    # Verify instantiating an Http instance works
    http = modern_httplib2.Http()
    assert isinstance(http, modern_httplib2.Http)


def test_package_metadata():
    assert modern_httplib2.__version__ == "1.32.0"
    assert modern_httplib2.__author__ == "Jay Lee"
    assert modern_httplib2.__email__ == "jay0lee@gmail.com"


def test_metadata_version_patched():
    import importlib.metadata

    patch()
    assert importlib.metadata.version("httplib2") == "1.32.0"
    assert importlib.metadata.version("modern-httplib2") == "1.32.0"


def test_glverlibs_hook():
    import types

    dummy = types.ModuleType("gamlib.glverlibs")
    dummy.GAM_VER_LIBS = ["cryptography", "httplib2", "filelock"]
    sys.modules["gamlib.glverlibs"] = dummy

    try:
        patch()
        assert "modern-httplib2" in dummy.GAM_VER_LIBS
        assert "httplib2" not in dummy.GAM_VER_LIBS

        unpatch()
        assert "httplib2" in dummy.GAM_VER_LIBS
        assert "modern-httplib2" not in dummy.GAM_VER_LIBS
    finally:
        sys.modules.pop("gamlib.glverlibs", None)
        patch()

