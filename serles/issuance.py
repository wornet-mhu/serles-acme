""" asynchronous order finalization (``asyncFinalize``)

With ``asyncFinalize`` enabled, the finalize request only checks the CSR, sets
the order to ``processing`` and returns. The (possibly slow) call to the
backend happens in a background thread; the client polls the order until it is
``valid`` or ``invalid`` (RFC 8555 §7.4).

Jobs are processed one at a time per process (e.g. certbot can't run in
parallel because of its lock). The worker thread is started on demand and ends
once the queue is empty. It is deliberately not a daemon thread: when the WSGI
worker exits (e.g. gunicorn on SIGTERM/SIGHUP), Python waits for it, so an
issuance in progress can finish. Jobs that have not started by then fail with
a "please retry" error.
"""

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone, timedelta

from .models import db, Certificate, IssuanceJob, Order, OrderStatus
from .certificate import sign_csr
from .exceptions import ACMEError

log = logging.getLogger(__name__)

# seconds clients should wait between polls of a processing order:
RETRY_AFTER = 5
# limit for interrupted jobs if the backend doesn't state its maximum runtime:
DEFAULT_STALE_AFTER = 600
# added to the backend's maximum runtime before a job is considered stale:
STALE_MARGIN = 30

_queue = deque()
_lock = threading.Lock()
_worker = None


def stale_after(backend):
    """ seconds after which a job is considered interrupted

    Backends can define a ``max_runtime`` attribute (seconds a sign() call can
    take at most, or None if unlimited); we add a safety margin to it.
    """
    max_runtime = getattr(backend, "max_runtime", None)
    if max_runtime:
        return max_runtime + STALE_MARGIN
    return DEFAULT_STALE_AFTER


def submit(app, order_id, sign_args):
    """ queue an order for signing

    The caller must have set the order to ``processing`` and added an
    IssuanceJob for it (committed), so the job can be accounted for.

    Args:
        app (flask.Flask): application, needed for database access.
        order_id (str): id of the order to finalize.
        sign_args (tuple): arguments for sign_csr(), from check_csr().
    """
    global _worker
    with _lock:
        _queue.append((order_id, sign_args))
        if _worker is None:
            _worker = threading.Thread(
                target=_work, args=(app,), name="serles-issuance"
            )
            _worker.start()


def _work(app):
    global _worker
    while True:
        with _lock:
            if not _queue:
                _worker = None
                return
            order_id, sign_args = _queue.popleft()
        with app.app_context():
            try:
                if threading.main_thread().is_alive():
                    _process(order_id, sign_args)
                else:  # shutting down; don't start new (long) jobs
                    _finish(order_id, error=ACMEError(
                        "server is shutting down, please retry", 503, "serverInternal"
                    ))
            except Exception:
                log.exception("issuance of %s failed unexpectedly", order_id)
                db.session.rollback()


def _process(order_id, sign_args):
    job = db.session.get(IssuanceJob, order_id)
    if job is None:  # already given up on (see fail_stale)
        return
    job.since = datetime.now(timezone.utc)
    db.session.commit()

    try:
        certificate = sign_csr(*sign_args)
    except ACMEError as e:
        _finish(order_id, error=e)
    except Exception as e:
        log.exception("backend failed to sign %s", order_id)
        _finish(order_id, error=ACMEError(str(e), 500, "serverInternal"))
    else:
        _finish(order_id, certificate=certificate)


def _finish(order_id, certificate=None, error=None):
    """ store the result, unless the order was given up on in the meantime """
    job = db.session.get(IssuanceJob, order_id)
    order = db.session.get(Order, order_id)
    if job is None or order is None or order.status != OrderStatus.processing:
        log.warning("discarding result for %s: order no longer processing", order_id)
        return
    if error is None:
        order.certificate = Certificate(certificate=certificate)
        order.status = OrderStatus.valid
    else:
        _set_invalid(order, error)
    db.session.delete(job)
    db.session.commit()


def _set_invalid(order, error):
    order.status = OrderStatus.invalid
    order.error = json.dumps({
        "type": f"urn:ietf:params:acme:error:{error.error_type}",
        "detail": str(error),
    })


def fail_stale(backend):
    """ set orders whose issuance was interrupted to invalid

    A job is stale if it was queued or started longer than stale_after() ago.
    Must be called within an application context.
    """
    limit = datetime.now(timezone.utc) - timedelta(seconds=stale_after(backend))
    for job in IssuanceJob.query.filter(IssuanceJob.since < limit).all():
        order = db.session.get(Order, job.order_id)
        if order is not None and order.status == OrderStatus.processing:
            log.warning("issuance of %s was interrupted", job.order_id)
            _set_invalid(order, ACMEError(
                "issuance was interrupted, please retry", 500, "serverInternal"
            ))
        db.session.delete(job)
    db.session.commit()
