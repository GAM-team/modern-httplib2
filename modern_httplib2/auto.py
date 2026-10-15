"""Automatically inject modern_httplib2 as httplib2 in sys.modules on import."""

from .patch import patch

patch()
