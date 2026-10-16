import os
import sys
from unittest import mock
import pytest
import tempfile
import httplib2


CERTIFI_CERTS_FILE = "unittest_certifi_file"
CUSTOM_CA_CERTS = "unittest_custom_ca_certs"


@pytest.fixture()
def clean_env():
    current_env_var = os.environ.get("HTTPLIB2_CA_CERTS")
    if current_env_var is not None:
        os.environ.pop("HTTPLIB2_CA_CERTS")
    yield
    if current_env_var is not None:
        os.environ["HTTPLIB2_CA_CERTS"] = current_env_var


@pytest.fixture()
def ca_certs_tmpfile(clean_env):
    tmpfd, tmpfile = tempfile.mkstemp()
    os.close(tmpfd)
    yield tmpfile
    os.remove(tmpfile)


@mock.patch("httplib2.certs.certifi_available", False)
@mock.patch("httplib2.certs.custom_ca_locater_available", False)
def test_certs_file_missing_raises_error(clean_env):
    with pytest.raises(RuntimeError, match="No CA certificates bundle found"):
        httplib2.certs.where()


@mock.patch("httplib2.certs.certifi_available", False)
@mock.patch("httplib2.certs.custom_ca_locater_available", False)
def test_certs_file_from_environment(ca_certs_tmpfile):
    os.environ["HTTPLIB2_CA_CERTS"] = ca_certs_tmpfile
    assert httplib2.certs.where() == ca_certs_tmpfile
    os.environ["HTTPLIB2_CA_CERTS"] = ""
    with pytest.raises(RuntimeError):
        httplib2.certs.where()
    os.environ.pop("HTTPLIB2_CA_CERTS")
    with pytest.raises(RuntimeError, match="No CA certificates bundle found"):
        httplib2.certs.where()


@mock.patch("httplib2.certs.certifi_where", mock.MagicMock(return_value=CERTIFI_CERTS_FILE))
@mock.patch("httplib2.certs.certifi_available", True)
@mock.patch("httplib2.certs.custom_ca_locater_available", False)
def test_certs_file_from_certifi(clean_env):
    assert httplib2.certs.where() == CERTIFI_CERTS_FILE


@mock.patch("httplib2.certs.certifi_available", False)
@mock.patch("httplib2.certs.custom_ca_locater_available", True)
@mock.patch("httplib2.certs.custom_ca_locater_where", mock.MagicMock(return_value=CUSTOM_CA_CERTS))
def test_certs_file_from_custom_getter(clean_env):
    assert httplib2.certs.where() == CUSTOM_CA_CERTS


@mock.patch("httplib2.certs.certifi_available", False)
@mock.patch("httplib2.certs.custom_ca_locater_available", False)
def test_with_certifi_removed_from_modules(ca_certs_tmpfile):
    if "certifi" in sys.modules:
        del sys.modules["certifi"]
    os.environ["HTTPLIB2_CA_CERTS"] = ca_certs_tmpfile
    assert httplib2.certs.where() == ca_certs_tmpfile
    os.environ.pop("HTTPLIB2_CA_CERTS")
    with pytest.raises(RuntimeError, match="No CA certificates bundle found"):
        httplib2.certs.where()
