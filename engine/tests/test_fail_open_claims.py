"""
Two checks that reported a weakness, or its absence, without measuring it.

    python engine/tests/test_fail_open_claims.py
    python -m pytest engine/tests/test_fail_open_claims.py

Why these exist.

Both defects here produced a confident statement in a document. Neither was
reachable by any existing test, which is how both survived to a release build.

1. **Any web server with no authentication was reported as having default
   credentials.** `LANScanner._try_http_creds` sent `Authorization: Basic
   admin:admin` and accepted any response under 400 as proof the login worked. A
   server that does not guard `/` with a password answers 200 whatever is in
   that header -- it never reads it -- so the first pair in `DEFAULT_CREDS` came
   back as a recovered credential for essentially every web server reached by a
   DEEP sweep.

   The frontend then promotes that into the strongest claim this tool can make:
   `archive.ts` scores it 100, CRITICAL, CONFIRMED, over the words "A working
   credential was recovered ... This is demonstrated access, not a theoretical
   weakness." A clean appliance was published as owned.

   The fix is to require both halves of the demonstration: the server refused
   the request without the credential, and accepted it with one.

2. **The SMBv1 signing check used the SMB2 bit positions**, one bit low. The
   byte offset was right, so it looked like it worked, and it inverted the answer
   for the single configuration the finding exists to catch -- a Windows host at
   its default `SecurityMode = 0x07`, signing enabled but not required, which is
   the ntlmrelayx-exploitable state. `smb_enum` reads SMB2 with the correct
   masks, so one host answered two different ways depending on which module got
   there first.

Neither test needs a network: the HTTP tests replace `urlopen` and the SMB tests
replace the socket, both with objects that answer the way a real server would.
"""
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import vuln_engine  # noqa: E402
from scanner.lan import LANScanner  # noqa: E402


# ── 1. HTTP default credentials ─────────────────────────────────────────────

class _Resp:
    """Just enough of an HTTP response for the check to read its status."""

    def __init__(self, status):
        self.status = status


def _http_scanner():
    """A scanner with no emit side effects; only `_try_http_creds` is exercised."""
    return LANScanner(lambda *a, **k: None)


def _with_urlopen(handler, fn):
    """Run `fn` with `urllib.request.urlopen` replaced by `handler`."""
    original = urllib.request.urlopen
    urllib.request.urlopen = handler
    try:
        return fn()
    finally:
        urllib.request.urlopen = original


def _responder(anonymous, authenticated):
    """
    A server that answers one way without credentials and another way with them.

    `anonymous` and `authenticated` are each an int status to return or an
    exception instance to raise.
    """
    calls = []

    def handler(req, timeout=None):
        has_auth = bool(req.get_header("Authorization"))
        calls.append("auth" if has_auth else "anon")
        outcome = authenticated if has_auth else anonymous
        if isinstance(outcome, BaseException):
            raise outcome
        return _Resp(outcome)

    handler.calls = calls
    return handler


def _http_error(code):
    return urllib.error.HTTPError("http://10.0.0.5/", code, "", {}, None)


def test_a_server_with_no_authentication_yields_no_credential():
    """
    The defect, stated as a test.

    200 to an anonymous request means there is no password on this resource, so
    there is no password to have recovered.
    """
    handler = _responder(anonymous=200, authenticated=200)
    cred = _with_urlopen(handler, lambda: _http_scanner()._try_http_creds("10.0.0.5", 80))
    assert cred is None, "an unauthenticated server was reported as having default creds"


def test_an_unauthenticated_server_is_never_even_offered_a_password():
    """
    No credential is attempted at all once the baseline comes back open.

    This matters beyond the false finding: these are real login attempts against
    a third party's host, and eight of them per service.
    """
    handler = _responder(anonymous=200, authenticated=200)
    _with_urlopen(handler, lambda: _http_scanner()._try_http_creds("10.0.0.5", 80))
    assert handler.calls == ["anon"], f"expected one anonymous probe, got {handler.calls}"


def test_a_challenged_server_that_accepts_the_password_is_a_finding():
    """The true positive still has to be reported, or the fix is just a mute."""
    handler = _responder(anonymous=_http_error(401), authenticated=200)
    cred = _with_urlopen(handler, lambda: _http_scanner()._try_http_creds("10.0.0.5", 80))
    assert cred == {"username": "admin", "password": "admin"}


def test_a_challenged_server_that_rejects_every_password_is_not_a_finding():
    handler = _responder(anonymous=_http_error(401), authenticated=_http_error(401))
    cred = _with_urlopen(handler, lambda: _http_scanner()._try_http_creds("10.0.0.5", 80))
    assert cred is None


def test_a_403_is_not_a_basic_auth_challenge():
    """
    403 is a refusal Basic auth does not answer.

    A server that returns it to an anonymous request is not guarding the
    resource with a password, so there is nothing here to demonstrate.
    """
    handler = _responder(anonymous=_http_error(403), authenticated=200)
    cred = _with_urlopen(handler, lambda: _http_scanner()._try_http_creds("10.0.0.5", 80))
    assert cred is None


def test_a_redirect_is_not_a_challenge():
    handler = _responder(anonymous=302, authenticated=200)
    cred = _with_urlopen(handler, lambda: _http_scanner()._try_http_creds("10.0.0.5", 80))
    assert cred is None


def test_a_server_error_is_not_a_challenge():
    handler = _responder(anonymous=_http_error(500), authenticated=200)
    cred = _with_urlopen(handler, lambda: _http_scanner()._try_http_creds("10.0.0.5", 80))
    assert cred is None


def test_an_unreachable_port_yields_no_credential():
    def handler(req, timeout=None):
        raise OSError("connection refused")

    cred = _with_urlopen(handler, lambda: _http_scanner()._try_http_creds("10.0.0.5", 80))
    assert cred is None


# ── 2. SMBv1 signing bits ───────────────────────────────────────────────────

class _FakeSmbSocket:
    """A socket that replays one SMB_COM_NEGOTIATE response."""

    def __init__(self, security_mode):
        # The parser reads response[4:8] for the SMB magic and response[39] for
        # SecurityMode, and requires len > 39.
        body = bytearray(64)
        body[4:8] = b"\xff\x53\x4d\x42"
        body[39] = security_mode
        self._response = bytes(body)

    def settimeout(self, _):
        pass

    def connect(self, _):
        pass

    def sendall(self, _):
        pass

    def recv(self, _):
        return self._response

    def close(self):
        pass


def _signing_result(security_mode):
    """`check_smb_signing`'s verdict for a host reporting `security_mode`."""
    original = vuln_engine.socket.socket
    vuln_engine.socket.socket = lambda *a, **k: _FakeSmbSocket(security_mode)
    try:
        return vuln_engine.VulnEngine(lambda *a, **k: None).check_smb_signing("10.0.0.9")
    finally:
        vuln_engine.socket.socket = original


def test_the_windows_default_is_reported_as_relay_vulnerable():
    """
    SecurityMode 0x07 -- user security, encrypted passwords, signing enabled but
    not required. The default on a Windows member server, and the state
    ntlmrelayx exploits.

    With the masks one bit low this computed `signing_required = True` and
    returned nothing at all, so the finding could never fire for the
    configuration it was written to catch.
    """
    result = _signing_result(0x07)
    assert result is not None, "the relay-vulnerable default raised no finding"
    assert result["code"] == "smb_signing"
    assert "not required" in result["vuln"].lower()
    assert result["severity"] == "MEDIUM"


def test_signing_required_raises_nothing():
    """0x0F sets the REQUIRED bit (0x08). A hardened host is not a finding."""
    assert _signing_result(0x0F) is None


def test_signing_fully_disabled_is_the_high_severity_case():
    """0x03: user security and encrypted passwords, no signing bits at all."""
    result = _signing_result(0x03)
    assert result is not None
    assert result["severity"] == "HIGH"
    assert "disabled" in result["vuln"].lower()


def test_encrypted_passwords_alone_does_not_count_as_signing():
    """
    0x02 is ENCRYPT_PASSWORDS, which the old masks read as "signing enabled".

    This is the inverse of the first test: that bit must not soften the verdict.
    """
    result = _signing_result(0x02)
    assert result is not None
    assert result["severity"] == "HIGH", \
        "the encrypt-passwords bit was mistaken for signing enabled"


def test_user_security_alone_does_not_count_as_signing():
    result = _signing_result(0x01)
    assert result is not None
    assert result["severity"] == "HIGH"


def test_signing_enabled_without_encryption_is_still_only_medium():
    """0x04 alone: signatures enabled, not required."""
    result = _signing_result(0x04)
    assert result is not None
    assert result["severity"] == "MEDIUM"


# -- 3. A CRITICAL finding for a file that is not there ----------------------

"""
`/config.json` (HIGH) and `/wp-config.php.bak` (CRITICAL) were the only two entries in
the `secrets` list with no content sanity check. Five of the seven had one. So any
server that answers 200 with its index page for an unknown path -- an nginx
`try_files ... /index.html`, an SPA catch-all, a custom 200 error page, a captive
portal -- produced "Exposed Web Secret: /wp-config.php.bak ... containing database
credentials" at CRITICAL for a file that does not exist.

The body was already read into `content` one line above the check. It simply was not
consulted for those two.

And `check_ftp_anon` built its HIGH finding *after* `ftp.quit()`. QUIT calls
`voidresp()`, which raises on a non-2xx reply and on a dropped connection -- routine
behaviour for embedded and NAS FTP daemons -- so the blanket `except Exception: return
None` swallowed a demonstrated anonymous login and the host was reported clean.
"""

SPA_INDEX = "<!DOCTYPE html>\n<html><head><title>App</title></head><body></body></html>"


class _WebResponse:
    def __init__(self, body, code=200):
        self._body = body.encode()
        self._code = code

    def getcode(self):
        return self._code

    def read(self, n=None):
        return self._body[:n] if n else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _web_secrets(body):
    """`check_web_secrets` against a server that answers every path with `body`."""
    import urllib.request as _ur
    original = _ur.urlopen
    _ur.urlopen = lambda req, timeout=None, context=None: _WebResponse(body)
    try:
        engine = vuln_engine.VulnEngine(lambda *a, **k: None)
        return engine.check_web_secrets("10.0.0.5", 80)
    finally:
        _ur.urlopen = original


def test_an_spa_catch_all_is_not_an_exposed_wordpress_config():
    # The CRITICAL one. This is the finding a reader acts on first.
    findings = _web_secrets(SPA_INDEX)
    paths = [f["vuln"] for f in findings]
    assert not any("wp-config" in p for p in paths), paths


def test_an_spa_catch_all_is_not_an_exposed_config_json():
    findings = _web_secrets(SPA_INDEX)
    assert not any("config.json" in f["vuln"] for f in findings), findings


def test_an_html_body_raises_nothing_at_all():
    # The catch-all guard: none of these files is ever an HTML document, so a path
    # added later cannot arrive without at least this much of a check.
    assert _web_secrets(SPA_INDEX) == []


def test_a_real_php_backup_is_still_reported():
    # The fix must not mute the true positive.
    findings = _web_secrets("<?php\n$DB_PASSWORD = 'hunter2';\n")
    assert any("wp-config" in f["vuln"] for f in findings), findings


def test_a_real_json_config_is_still_reported():
    findings = _web_secrets('{"db": {"password": "hunter2"}}')
    assert any("config.json" in f["vuln"] for f in findings), findings


def test_an_anonymous_ftp_login_survives_a_server_that_errors_on_quit():
    """
    The login already succeeded; QUIT failing cannot unmake that.

    `ftplib.FTP.quit()` sends QUIT and then reads the reply, raising on a non-2xx
    response or a dropped connection. The finding was sequenced after it.
    """
    class _FTP:
        def connect(self, *a, **k):
            pass

        def login(self, *a, **k):
            pass

        def quit(self):
            raise OSError("connection reset by peer")

        def close(self):
            pass

    original = vuln_engine.FTP
    vuln_engine.FTP = _FTP
    try:
        result = vuln_engine.VulnEngine(lambda *a, **k: None).check_ftp_anon("10.0.0.5")
    finally:
        vuln_engine.FTP = original

    assert result is not None, "a demonstrated anonymous login was discarded"
    assert result["code"] == "ftp_anonymous"
    assert result["severity"] == "HIGH"


def test_a_refused_ftp_login_is_still_not_a_finding():
    class _FTP:
        def connect(self, *a, **k):
            pass

        def login(self, *a, **k):
            raise Exception("530 Login incorrect")

        def quit(self):
            pass

        def close(self):
            pass

    original = vuln_engine.FTP
    vuln_engine.FTP = _FTP
    try:
        assert vuln_engine.VulnEngine(lambda *a, **k: None).check_ftp_anon("10.0.0.5") is None
    finally:
        vuln_engine.FTP = original


def _main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed.append(name)
            print(f"  FAIL  {name}: {e or 'assertion failed'}")
        except Exception as e:
            failed.append(name)
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
