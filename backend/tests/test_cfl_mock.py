from app.services.cfl_mock_service import CFLMockService
from app.services.cfl_real_service import CFLRealError, CFLRealService
from app.services.cfl_service import CFLService


def test_mock_cfl_sign_verify():
    cfl = CFLMockService()
    data = b"payload"
    signature = cfl.sign(data)
    assert cfl.verify("student", data, signature) is True
    assert cfl.verify("student", b"tampered", signature) is False


def test_cfl_service_defaults_to_mock():
    status = CFLService().status()
    assert status["mode"] in {"mock", "real"}
    assert "real" in status


def test_real_signature_parser_rejects_bad_length():
    cfl = CFLRealService("missing.dll")
    try:
        cfl._signature_blob("abc")
    except CFLRealError as exc:
        assert exc.operation == "parse_signature"
    else:
        raise AssertionError("bad signature length was accepted")
