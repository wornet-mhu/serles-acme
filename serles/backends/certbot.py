import atexit
import subprocess
import tempfile
import threading
import json
import os

from subprocess import STDOUT, PIPE

# certbot processes that are currently running. Kept so they can be terminated
# gracefully when serles shuts down (see _terminate_running).
_running = set()
_running_lock = threading.Lock()


def _terminate(proc, grace):
    """ stop a certbot process, giving it a chance to clean up

    certbot removes challenge records (e.g. DNS TXT records) and its lock files
    from an exit handler that runs on SIGTERM, but not on SIGKILL. So we send
    SIGTERM first and only resort to SIGKILL if it does not exit in time.

    Args:
        proc (subprocess.Popen): the process to stop.
        grace (int): seconds to wait after SIGTERM before sending SIGKILL.

    Returns:
        bytes: remaining output of the process.
    """
    proc.terminate()
    try:
        output, _ = proc.communicate(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.kill()
        output, _ = proc.communicate()
    return output or b""


@atexit.register
def _terminate_running():
    """ send SIGTERM to all certbot processes still running at exit

    Without this, a certbot started from a (daemon) thread would be orphaned
    when serles exits and keep running, holding certbot's lock.
    """
    with _running_lock:
        procs = list(_running)
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()


class Backend:
    """ Serles Backend for certbot

    Backend will pass the certificate signing request to an already configured
    certbot installation.

    Example use cases:
       1. Want actual trusted certs without using an internal CA (you want it
          to work in browsers/etc. out of the box)
       2. Don't want the services externally exposed (internal
          services/development only)
       3. Don't want the internal services having control over your external
          DNS (random developers/users)
       4. Have an intermediate server running serles that you are willing to
          grant external DNS update rights to.

    This allows any internal entity to transparently use serles ACME CA with
    http-01 validation, but the actual signing requests are delegated to
    external ACME CA.

    Contributed by Nathan Neulinger.
    """

    # seconds certbot gets to clean up after SIGTERM before it is killed:
    terminate_grace = 30

    def __init__(self, config):
        self.path = "/usr/bin/certbot"
        self.config = None
        self.config_file = None
        self.timeout = None

        if "certbot" in config:
            if "path" in config["certbot"]:
                self.path = config["certbot"]["path"]
            if "config" in config["certbot"]:
                self.config = config["certbot"]["config"]
            if "config-file" in config["certbot"]:
                self.config_file = config["certbot"]["config-file"]
            if "timeout" in config["certbot"]:
                try:
                    self.timeout = int(config["certbot"]["timeout"])
                except ValueError:
                    self.timeout = 0
                if self.timeout <= 0:
                    raise Exception(
                        "certbot.timeout must be a positive number of seconds"
                    )

        if self.config_file and self.config:
            raise Exception(
                "cannot specify both certbot.config and certbot.config-file in config.ini"
            )

        if not self.config_file and not self.config:
            # Ensure we load in our own config and do NOT fall back to system level certbot default config file
            raise Exception(
                "no config specified, need either certbot.config or certbot.config-file"
            )

        if not os.path.exists(self.path):
            raise Exception(
                f"certbot not found at '{self.path}', please specify correct path in certbot.path setting in config.ini"
            )

        if not os.access(self.path, os.X_OK):
            raise Exception(f"certbot '{self.path}' not executable")

    def sign(self, csr, subjectDN, subjectAltNames, email):
        with tempfile.TemporaryDirectory(prefix="serles-certbot") as tmpdir:

            # Write explicit configuration to temporary file if a config file is not provided
            certbot_config_arg = self.config_file
            if self.config:
                ini_file = f"{tmpdir}/certbot-cli.ini"
                with open(ini_file, "w") as fh:
                    fh.write(self.config)
                certbot_config_arg = ini_file

            csr_file = f"{tmpdir}/csr.pem"
            with open(csr_file, "wb") as fh:
                fh.write(csr)

            cert_file = f"{tmpdir}/cert.pem"
            fullchain_file = f"{tmpdir}/fullchain.pem"
            chain_file = f"{tmpdir}/chain.pem"

            cmd = [
                self.path,
                "certonly",
                "--config", certbot_config_arg,
                "--non-interactive",
                "--csr", csr_file,
                "--cert-path", cert_file,
                "--fullchain-path", fullchain_file,
                "--chain-path", chain_file
            ]

            for csr_san in subjectAltNames:
                cmd.extend(["-d", csr_san])

            # Note: subprocess.run(timeout=...) would SIGKILL certbot, which
            # leaves challenge records and lock files behind. _run() sends
            # SIGTERM instead, so certbot can clean up.
            returncode, output, timed_out = self._run(cmd)

            if timed_out:
                return (
                    None,
                    f"certbot timed out after {self.timeout}s and was terminated; output:\n{output}"
                )

            if returncode:
                return (
                    None,
                    f"certbot exited with error {returncode} and output:\n{output}"
                )

            with open(fullchain_file, "r") as new_chain:
                return new_chain.read(), None

    def _run(self, cmd):
        """ run certbot, stopping it gracefully on timeout or interruption

        Args:
            cmd (list): command line to execute.

        Returns:
            (int, str, bool): return code, combined stdout/stderr and whether
            certbot was terminated because it exceeded `self.timeout`.
        """
        proc = subprocess.Popen(cmd, stdout=PIPE, stderr=STDOUT)
        with _running_lock:
            _running.add(proc)
        try:
            try:
                output, _ = proc.communicate(timeout=self.timeout)
                timed_out = False
            except subprocess.TimeoutExpired:
                output = _terminate(proc, self.terminate_grace)
                timed_out = True
            except BaseException:
                # e.g. SystemExit when gunicorn aborts the worker on its own
                # timeout: make sure certbot still gets SIGTERM (and not just
                # orphaned or SIGKILLed), then re-raise.
                proc.terminate()
                raise
        finally:
            with _running_lock:
                _running.discard(proc)

        return proc.returncode, output.decode("utf-8", errors="replace"), timed_out
