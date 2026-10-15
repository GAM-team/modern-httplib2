"""Monkey-patching utilities to transparently replace legacy httplib2 with modern_httplib2."""

import importlib
import importlib.metadata
import sys

_SUBMODULES = ("auth", "certs", "decode", "error", "iri2uri")
_ORIGINAL_MODULES = {}
_META_PATH_HOOK = None
_ORIG_METADATA_VERSION = None


def _patch_glverlibs_module(module) -> None:
    libs = getattr(module, "GAM_VER_LIBS", None)
    if isinstance(libs, list):
        if "httplib2" in libs:
            idx = libs.index("httplib2")
            libs[idx] = "modern-httplib2"
        elif "modern-httplib2" not in libs:
            libs.append("modern-httplib2")


def _unpatch_glverlibs_module(module) -> None:
    libs = getattr(module, "GAM_VER_LIBS", None)
    if isinstance(libs, list):
        if "modern-httplib2" in libs:
            idx = libs.index("modern-httplib2")
            libs[idx] = "httplib2"


class _GAMVerLibsFinder:
    """Import hook to patch gamlib.glverlibs.GAM_VER_LIBS when it is imported."""

    def find_spec(self, fullname, path, target=None):
        if fullname == "glverlibs" or fullname.endswith(".glverlibs"):
            for finder in sys.meta_path:
                if finder is self:
                    continue
                if hasattr(finder, "find_spec"):
                    spec = finder.find_spec(fullname, path, target)
                    if spec is not None and spec.loader is not None:
                        orig_loader = spec.loader

                        class _WrappedLoader:
                            def __init__(self, loader):
                                self._orig_loader = loader

                            def create_module(self, s):
                                if hasattr(self._orig_loader, "create_module"):
                                    return self._orig_loader.create_module(s)
                                return None

                            def exec_module(self, module):
                                self._orig_loader.exec_module(module)
                                _patch_glverlibs_module(module)

                            def __getattr__(self, name):
                                return getattr(self._orig_loader, name)

                        spec.loader = _WrappedLoader(orig_loader)
                        return spec
        return None


def _patch_metadata_version() -> None:
    global _ORIG_METADATA_VERSION
    if _ORIG_METADATA_VERSION is None:
        _ORIG_METADATA_VERSION = importlib.metadata.version

        def _patched_version(distribution_name: str) -> str:
            norm = distribution_name.lower().replace("_", "-")
            if norm in ("httplib2", "modern-httplib2"):
                import modern_httplib2

                return getattr(modern_httplib2, "__version__", "1.32.0")
            return _ORIG_METADATA_VERSION(distribution_name)

        importlib.metadata.version = _patched_version

    for gam_name in ("gam", "__main__"):
        gam_mod = sys.modules.get(gam_name)
        if gam_mod and hasattr(gam_mod, "lib_version"):
            gam_mod.lib_version = importlib.metadata.version


def _unpatch_metadata_version() -> None:
    global _ORIG_METADATA_VERSION
    if _ORIG_METADATA_VERSION is not None:
        importlib.metadata.version = _ORIG_METADATA_VERSION
        _ORIG_METADATA_VERSION = None


def patch(target: str = "httplib2") -> None:
    """Inject modern_httplib2 into sys.modules under target name (default: 'httplib2').

    This ensures third-party libraries (e.g. google-api-python-client,
    google-auth-httplib2) transparently obtain modern_httplib2 when they execute
    'import httplib2'.
    """
    global _META_PATH_HOOK
    import modern_httplib2

    # Save any existing module in case unpatch is called
    if target in sys.modules and sys.modules[target] is not modern_httplib2:
        _ORIGINAL_MODULES[target] = sys.modules[target]

    sys.modules[target] = modern_httplib2

    # Mirror submodules so 'import httplib2.error' etc. resolve cleanly
    for sub in _SUBMODULES:
        target_sub = f"{target}.{sub}"
        if target_sub in sys.modules:
            _ORIGINAL_MODULES[target_sub] = sys.modules[target_sub]
        try:
            submod = importlib.import_module(f"modern_httplib2.{sub}")
            sys.modules[target_sub] = submod
        except ImportError:
            pass

    # Patch importlib.metadata.version
    _patch_metadata_version()

    # Install meta_path finder hook for glverlibs
    if _META_PATH_HOOK is None:
        _META_PATH_HOOK = _GAMVerLibsFinder()
        sys.meta_path.insert(0, _META_PATH_HOOK)

    # Patch any already-loaded glverlibs modules
    for name, mod in list(sys.modules.items()):
        if mod is not None and (name == "glverlibs" or name.endswith(".glverlibs")):
            _patch_glverlibs_module(mod)


def unpatch(target: str = "httplib2") -> None:
    """Restore original sys.modules state prior to patch()."""
    global _META_PATH_HOOK

    target_keys = [k for k in sys.modules if k == target or k.startswith(f"{target}.")]
    for k in target_keys:
        if k in _ORIGINAL_MODULES:
            sys.modules[k] = _ORIGINAL_MODULES.pop(k)
        else:
            sys.modules.pop(k, None)

    # Remove meta_path hook
    if _META_PATH_HOOK is not None:
        if _META_PATH_HOOK in sys.meta_path:
            sys.meta_path.remove(_META_PATH_HOOK)
        _META_PATH_HOOK = None

    # Unpatch any loaded glverlibs modules
    for name, mod in list(sys.modules.items()):
        if mod is not None and (name == "glverlibs" or name.endswith(".glverlibs")):
            _unpatch_glverlibs_module(mod)

    # Restore metadata version
    _unpatch_metadata_version()


def is_patched(target: str = "httplib2") -> bool:
    """Return True if sys.modules[target] points to modern_httplib2."""
    import modern_httplib2

    return sys.modules.get(target) is modern_httplib2
