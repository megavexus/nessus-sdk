import pytest
from sc_sdk.api import SCApi
from sc_sdk.exceptions import WrongCredentialsException, BadLoginException


def test_login_user_password(connection_data):
    scanner = SCApi(
        host=connection_data['host'],
        port=connection_data['port'],
        scheme=connection_data['scheme'],
        username=connection_data['username'],
        password=connection_data['password'],
        unsecure=connection_data['unsafe'],
    )
    assert len(scanner._session.headers) > 0


def test_login_user_bad_password(connection_data):
    with pytest.raises(BadLoginException):
        scanner = SCApi(
            host=connection_data['host'],
            port=connection_data['port'],
            scheme=connection_data['scheme'],
            username=connection_data['username'],
            password="hola123",
            unsecure=connection_data['unsafe'],
        )
