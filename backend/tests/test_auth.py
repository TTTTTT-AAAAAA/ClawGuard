from app.security.jwt_utils import create_access_token, decode_access_token


def test_jwt_round_trip():
    token = create_access_token("admin", "admin")
    payload = decode_access_token(token)
    assert payload["sub"] == "admin"
    assert payload["role"] == "admin"

