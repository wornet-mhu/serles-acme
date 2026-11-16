import base64
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

import flask
import jwcrypto.jwk

import serles as main
from serles import issuance
from serles.models import IssuanceJob, OrderStatus

import MockBackend


def config_with(backend, async_finalize=True):
    cfg = {
        "asyncFinalize": async_finalize,
        "forceTemplateDN": False,
        "subjectNameTemplate": "CN={SAN[0]}",
        "removeRootCAFromChain": False,
    }
    return lambda: (cfg, backend)


class FailingBackend:
    def sign(self, csr, subjectDN, subjectAltNames, email):
        return None, "backend says no"


class BlockingBackend(MockBackend.Backend):
    """ signs only once `release` is set """

    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()

    def sign(self, *args):
        self.started.set()
        assert self.release.wait(10)
        return super().sign(*args)


class AsyncFinalizeTester(unittest.TestCase):
    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.config["PROPAGATE_EXCEPTIONS"] = True
        # a file, not :memory:, so each thread gets its own connection (as in
        # production; with :memory: all threads would share one connection)
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        db_file = os.path.join(tmpdir.name, "serles.db")
        self.app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_file}"
        self.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        main.api.init_app(self.app)
        main.db.init_app(self.app)
        with self.app.app_context():
            main.db.create_all()
        self.app.register_error_handler(Exception, main.exception_handler)

        self.payload = {}
        self.kid = "foo"
        self.jwk = json.loads(jwcrypto.jwk.JWK.generate(kty="RSA", size=2048).export())

        @self.app.before_request
        def parse_jws():
            from flask import g

            g.kid = self.kid
            g.jwk = self.jwk
            g.payload = self.payload

        self.client = self.app.test_client()
        self.addCleanup(self.wait_for_worker)

    def wait_for_worker(self, timeout=10):
        deadline = time.monotonic() + timeout
        while issuance._worker is not None:
            self.assertLess(time.monotonic(), deadline, "worker still running")
            time.sleep(0.05)

    def use_backend(self, backend, async_finalize=True):
        get_config = config_with(backend, async_finalize)
        for target in (main.views, main.certificate):
            p = patch.object(target, "get_config", get_config)
            p.start()
            self.addCleanup(p.stop)

    def ready_order(self, identifier="example.test"):
        """ create an account and an order in state ready; returns order url """
        c = self.client
        r = c.post("/newAccount")
        _, _, self.kid = r.headers.get("Location").rpartition("/")
        self.payload = {"identifiers": [{"type": "dns", "value": identifier}]}
        r = c.post("/newOrder")
        order_url = r.headers.get("Location")
        authz = c.post(r.json["authorizations"][0])
        with patch.object(main.challenge, "http_challenge", lambda x: (None, None)):
            c.post(authz.json["challenges"][0]["url"])
        self.assertEqual(c.post(order_url).json["status"], "ready")
        return order_url

    def finalize(self, order_url):
        self.payload = {
            "csr": base64.b64encode(
                open("data_example.test.csr.bin", "rb").read()
            ).decode()
        }
        return self.client.post(order_url + "/finalize")

    def wait_until_done(self, order_url, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = self.client.post(order_url)
            if r.json["status"] != "processing":
                return r
            time.sleep(0.05)
        self.fail("order still processing")

    def job_count(self):
        with self.app.app_context():
            return IssuanceJob.query.count()

    def test_async_finalize(self):
        self.use_backend(MockBackend.Backend(None))
        order_url = self.ready_order()

        r = self.finalize(order_url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["status"], "processing")
        self.assertEqual(r.headers.get("Retry-After"), str(issuance.RETRY_AFTER))
        self.assertEqual(r.headers.get("Location"), order_url)

        r = self.wait_until_done(order_url)
        self.assertEqual(r.json["status"], "valid")
        self.assertIsNone(r.headers.get("Retry-After"))
        self.assertEqual(self.job_count(), 0)
        r = self.client.post(r.json["certificate"])
        self.assertEqual(r.status_code, 200)

        # finalizing again is not allowed
        r = self.finalize(order_url)
        self.assertEqual(r.json["type"], "urn:ietf:params:acme:error:orderNotReady")

    def test_async_finalize_backend_error(self):
        self.use_backend(FailingBackend())
        order_url = self.ready_order()
        self.assertEqual(self.finalize(order_url).json["status"], "processing")

        r = self.wait_until_done(order_url)
        self.assertEqual(r.json["status"], "invalid")
        self.assertEqual(r.json["error"]["type"], "urn:ietf:params:acme:error:badCSR")
        self.assertEqual(r.json["error"]["detail"], "backend says no")
        self.assertNotIn("certificate", r.json)
        self.assertEqual(self.job_count(), 0)

    def test_async_finalize_bad_csr(self):
        # the CSR is checked synchronously; nothing is queued
        self.use_backend(MockBackend.Backend(None))
        order_url = self.ready_order(identifier="other.test")
        r = self.finalize(order_url)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json["type"], "urn:ietf:params:acme:error:badCSR")
        self.assertEqual(self.client.post(order_url).json["status"], "ready")
        self.assertEqual(self.job_count(), 0)

    def test_processing_order_has_retry_after(self):
        backend = BlockingBackend()
        self.use_backend(backend)
        order_url = self.ready_order()
        self.finalize(order_url)
        self.assertTrue(backend.started.wait(10))

        r = self.client.post(order_url)
        self.assertEqual(r.json["status"], "processing")
        self.assertEqual(r.headers.get("Retry-After"), str(issuance.RETRY_AFTER))

        backend.release.set()
        self.assertEqual(self.wait_until_done(order_url).json["status"], "valid")

    def test_result_discarded_after_fail_stale(self):
        # an order given up on must not become valid afterwards
        backend = BlockingBackend()
        self.use_backend(backend)
        order_url = self.ready_order()
        self.finalize(order_url)
        self.assertTrue(backend.started.wait(10))

        with self.app.app_context():
            with patch.object(issuance, "stale_after", lambda backend: -1):
                issuance.fail_stale(backend)
        r = self.client.post(order_url)
        self.assertEqual(r.json["status"], "invalid")
        self.assertIn("interrupted", r.json["error"]["detail"])

        backend.release.set()
        self.wait_for_worker()
        r = self.client.post(order_url)
        self.assertEqual(r.json["status"], "invalid")
        self.assertNotIn("certificate", r.json)

    def test_fail_stale(self):
        self.use_backend(MockBackend.Backend(None))
        order_url = self.ready_order()
        _, _, order_id = order_url.rpartition("/")
        now = datetime.now(timezone.utc)
        with self.app.app_context():
            order = main.db.session.get(main.Order, order_id)
            order.status = OrderStatus.processing
            main.db.session.add(IssuanceJob(order_id=order_id, since=now))
            main.db.session.commit()

            # young job: untouched
            issuance.fail_stale(Mock(max_runtime=270))
            self.assertEqual(order.status, OrderStatus.processing)
            self.assertEqual(IssuanceJob.query.count(), 1)

            # old job: order invalid, job gone
            IssuanceJob.query.first().since = now - timedelta(seconds=301)
            main.db.session.commit()
            issuance.fail_stale(Mock(max_runtime=270))
            self.assertEqual(order.status, OrderStatus.invalid)
            self.assertEqual(IssuanceJob.query.count(), 0)

    def test_shutdown_fails_queued_jobs(self):
        self.use_backend(MockBackend.Backend(None))
        order_url = self.ready_order()
        dead_main_thread = Mock(is_alive=lambda: False)
        with patch.object(issuance.threading, "main_thread", lambda: dead_main_thread):
            self.finalize(order_url)
            r = self.wait_until_done(order_url)
        self.assertEqual(r.json["status"], "invalid")
        self.assertIn("shutting down", r.json["error"]["detail"])
        self.assertEqual(self.job_count(), 0)

    def test_sync_finalize_unchanged(self):
        self.use_backend(MockBackend.Backend(None), async_finalize=False)
        order_url = self.ready_order()
        r = self.finalize(order_url)
        self.assertEqual(r.json["status"], "valid")
        self.assertIsNone(r.headers.get("Retry-After"))
        self.assertEqual(self.job_count(), 0)

    def test_stale_after(self):
        self.assertEqual(issuance.stale_after(Mock(max_runtime=270)), 300)
        self.assertEqual(issuance.stale_after(Mock(max_runtime=None)), 600)
        self.assertEqual(issuance.stale_after(object()), 600)


if __name__ == "__main__":
    unittest.main()
