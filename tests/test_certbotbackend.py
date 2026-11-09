import os
import tempfile
import unittest
import unittest.mock
from unittest.mock import Mock
from serles.backends import certbot as CertbotBackend

tmp = tempfile.mkdtemp()

good_config = {
    "certbot": {
        "config": f"#",
    }
}

both_config = {
    "certbot": {
        "config": "# a config file",
        "config-file": "/whatever",
    }
}


class FakePopen:
    """ stand-in for subprocess.Popen; behaviour is set via class attributes

    - write_cert: write a fake certificate to the --fullchain-path
    - returncode: exit status reported once the process has finished
    - hang: number of communicate() calls that raise TimeoutExpired
    """

    write_cert = True
    returncode = 0
    hang = 0
    instances = []

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.kwargs = kwargs
        self.calls = []
        self.timeouts = []
        self.hang = type(self).hang
        self.returncode = None
        FakePopen.instances.append(self)

    def communicate(self, timeout=None):
        self.timeouts.append(timeout)
        if self.hang:
            self.hang -= 1
            raise CertbotBackend.subprocess.TimeoutExpired(self.cmd, timeout)
        if self.write_cert and not self.calls:
            open(self.cmd[10], "w").write("fake cert")
        self.returncode = -15 if "terminate" in self.calls else type(self).returncode
        return b"the output", None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.calls.append("terminate")

    def kill(self):
        self.calls.append("kill")


def fake_popen(**attrs):
    FakePopen.instances = []
    return type("FakePopenVariant", (FakePopen,), attrs)


class CertbotBackendTester(unittest.TestCase):
    def setUp(self):
        os.chdir(os.path.dirname(__file__))

    def test_backend_okconfig(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: True):
            config = dict(certbot=dict(path="/usr/local/bin/certbot", config="x"))
            backend = CertbotBackend.Backend(config)
            self.assertNotEqual(backend, None)

    def test_backend_nocertbot(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: False
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: False):
            self.assertRaisesRegex(
                Exception,
                "certbot not found at '/usr/bin/certbot', please specify correct path in certbot.path setting in config.ini",
                CertbotBackend.Backend,
                good_config,
            )

    def test_backend_noexec(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: False):
            self.assertRaisesRegex(
                Exception,
                "certbot '/usr/bin/certbot' not executable",
                CertbotBackend.Backend,
                good_config,
            )

    def test_backend_noconfig(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: True):
            config = dict(certbot=dict())
            self.assertRaisesRegex(
                Exception,
                "no config specified, need either certbot.config or certbot.config-file",
                CertbotBackend.Backend,
                config,  # missing config key
            )

    def test_backend_fullconfig(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: True):
            self.assertRaisesRegex(
                Exception,
                "cannot specify both certbot.config and certbot.config-file in config.ini",
                CertbotBackend.Backend,
                both_config,
            )

    def patched(self, popen):
        return unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(
            CertbotBackend.os, "access", lambda a, b: True
        ), unittest.mock.patch.object(
            CertbotBackend.subprocess, "Popen", popen
        )

    def sign(self, config, popen):
        p1, p2, p3 = self.patched(popen)
        with p1, p2, p3:
            backend = CertbotBackend.Backend(config)
            csr_input = open("data_example.test.csr.bin", "rb").read()
            return backend.sign(csr_input, "dn", "san", "email")

    def test_sign(self):
        chain, error = self.sign(good_config, fake_popen())
        self.assertEqual(error, None)
        self.assertEqual(chain[:28], "fake cert")
        proc = FakePopen.instances[0]
        self.assertEqual(proc.timeouts, [None])  # no timeout by default
        self.assertEqual(proc.calls, [])
        self.assertEqual(CertbotBackend._running, set())

    def test_sign_failed(self):
        chain, error = self.sign(good_config, fake_popen(returncode=1, write_cert=False))
        self.assertEqual(chain, None)
        self.assertEqual(
            error, "certbot exited with error 1 and output:\nthe output"
        )

    def test_timeout_config(self):
        for value, expected in (("300", 300), (" 45 ", 45)):
            p1, p2, p3 = self.patched(fake_popen())
            with p1, p2, p3:
                config = dict(certbot=dict(config="x", timeout=value))
                self.assertEqual(CertbotBackend.Backend(config).timeout, expected)

    def test_timeout_config_invalid(self):
        for value in ("0", "-5", "abc", ""):
            p1, p2, p3 = self.patched(fake_popen())
            with p1, p2, p3:
                config = dict(certbot=dict(config="x", timeout=value))
                self.assertRaisesRegex(
                    Exception,
                    "certbot.timeout must be a positive number of seconds",
                    CertbotBackend.Backend,
                    config,
                )

    def test_sign_timeout_terminates(self):
        config = dict(certbot=dict(config="x", timeout="42"))
        chain, error = self.sign(config, fake_popen(hang=1, write_cert=False))
        self.assertEqual(chain, None)
        self.assertEqual(
            error,
            "certbot timed out after 42s and was terminated; output:\nthe output",
        )
        proc = FakePopen.instances[0]
        self.assertEqual(proc.timeouts, [42, CertbotBackend.Backend.terminate_grace])
        self.assertEqual(proc.calls, ["terminate"])  # SIGTERM only, no SIGKILL
        self.assertEqual(CertbotBackend._running, set())

    def test_sign_timeout_kills_if_term_ignored(self):
        config = dict(certbot=dict(config="x", timeout="42"))
        chain, error = self.sign(config, fake_popen(hang=2, write_cert=False))
        self.assertEqual(chain, None)
        self.assertTrue(error.startswith("certbot timed out after 42s"))
        self.assertEqual(FakePopen.instances[0].calls, ["terminate", "kill"])

    def test_sign_interrupted_terminates(self):
        # e.g. gunicorn aborting the worker raises SystemExit in the worker
        class Interrupted(FakePopen):
            def communicate(self, timeout=None):
                raise SystemExit(1)

        FakePopen.instances = []
        with self.assertRaises(SystemExit):
            self.sign(good_config, Interrupted)
        self.assertEqual(FakePopen.instances[0].calls, ["terminate"])
        self.assertEqual(CertbotBackend._running, set())

    def test_terminate_running_at_exit(self):
        running, finished = FakePopen([]), FakePopen([])
        finished.returncode = 0
        with unittest.mock.patch.object(
            CertbotBackend, "_running", {running, finished}
        ):
            CertbotBackend._terminate_running()
        self.assertEqual(running.calls, ["terminate"])
        self.assertEqual(finished.calls, [])

    def test_sign_timeout_real_process(self):
        # end-to-end with a real child process: certbot is stood in for by a
        # shell script that cleans up on SIGTERM, like certbot does.
        with tempfile.TemporaryDirectory() as d:
            script = os.path.join(d, "certbot")
            marker = os.path.join(d, "cleaned-up")
            with open(script, "w") as fh:
                fh.write(
                    "#!/bin/sh\n"
                    f"trap 'echo cleanup; touch {marker}; exit 1' TERM\n"
                    "echo waiting for validation\n"
                    "while :; do sleep 0.1; done\n"
                )
            os.chmod(script, 0o755)
            backend = CertbotBackend.Backend(
                dict(certbot=dict(path=script, config="x", timeout="1"))
            )
            backend.terminate_grace = 5
            csr_input = open("data_example.test.csr.bin", "rb").read()
            chain, error = backend.sign(csr_input, "dn", ["example.test"], "email")
            self.assertEqual(chain, None)
            self.assertIn("certbot timed out after 1s", error)
            self.assertIn("waiting for validation", error)
            self.assertIn("cleanup", error)
            self.assertTrue(os.path.exists(marker))
