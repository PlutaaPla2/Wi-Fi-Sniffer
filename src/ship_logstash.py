#!/usr/bin/env python3
"""
Logstash shipping sink for night_sniffer_v3.py.

One CSV row in, one Logstash event out, over TCP, on a background worker thread.

The CSV remains the source of truth. ship_row() is called only after the row has
been written and flushed to disk, and every failure inside it is swallowed and
counted rather than raised — a shipping fault must cost the event, never the
capture.

Optional at runtime: if python-logstash-async is not installed this module still
imports cleanly and init_shipper() reports the problem. Capture is unaffected.
"""

import logging
import threading

try:
    from logstash_async.handler import AsynchronousLogstashHandler
    from logstash_async.formatter import LogstashFormatter
    import logstash_async.constants as ls_constants
    _IMPORT_ERROR: Exception | None = None
except ImportError as exc:            # optional dependency
    AsynchronousLogstashHandler = None
    LogstashFormatter = None
    ls_constants = None
    _IMPORT_ERROR = exc

log = logging.getLogger(__name__)

# ── Worker tunables ─────────────────────────────────────────────────────────
# Library defaults batch every 5s / 50 events, which is sensible in production
# and unhelpfully slow when you are staring at a netcat listener waiting to see
# whether anything arrives at all. Tightened for the test; raise later.
SHIP_FLUSH_INTERVAL = 1.0    # seconds between worker flushes
SHIP_FLUSH_COUNT    = 10     # or this many queued events, whichever first
SHIP_SOCKET_TIMEOUT = 5.0    # seconds before a connect/send attempt gives up

# Same pattern as MAX_FRAME_ERROR_LOGS in the sniffer: log the first few in
# full, then count only, so a systematically failing sink cannot flood stdout.
MAX_SHIP_ERROR_LOGS = 5

_ship_logger:  logging.Logger | None = None
_ship_handler = None
_shipped      = 0
_ship_errors  = 0
_init_lock    = threading.Lock()


def shipping_enabled() -> bool:
    """True once init_shipper() has succeeded. Cheap; safe to call per frame."""
    return _ship_logger is not None


def init_shipper(host: str, port: int, database_path: str | None = None) -> bool:
    """
    Wire up the async Logstash handler. Returns False if it could not be built.

    The caller is expected to treat False as fatal when --ship was requested
    explicitly: capturing without shipping during a shipping test looks like a
    successful run and is worse than an early exit.

    ``database_path`` is the worker's spool. None keeps queued events in memory
    (lost on process death, no SD-card writes); a path gives an SQLite spool
    that survives restarts at the cost of a disk write per event.
    """
    global _ship_logger, _ship_handler

    with _init_lock:
        if _ship_logger is not None:
            return True

        if AsynchronousLogstashHandler is None:
            log.error("Shipping requires python-logstash-async: %s", _IMPORT_ERROR)
            log.error("  pip install python-logstash-async")
            return False

        # Module-level knobs, not constructor kwargs, in this library.
        ls_constants.QUEUED_EVENTS_FLUSH_INTERVAL = SHIP_FLUSH_INTERVAL
        ls_constants.QUEUED_EVENTS_FLUSH_COUNT    = SHIP_FLUSH_COUNT
        ls_constants.SOCKET_TIMEOUT               = SHIP_SOCKET_TIMEOUT

        try:
            handler = AsynchronousLogstashHandler(
                host=host,
                port=port,
                database_path=database_path,
                ssl_enable=False,     # explicit: the WSL2 test stack has TLS off
                # TCP is this library's default transport; naming it here would
                # only add a version-specific kwarg that could stop existing.
            )
            handler.setFormatter(LogstashFormatter(
                message_type="night_sniffer",
                # Flatten our fields to the top level of the event instead of
                # nesting them under "extra". Verify the actual envelope with
                # the netcat step in the task doc — do not assume.
                extra_prefix=None,
            ))
        except Exception as exc:
            log.error("Could not build Logstash handler for %s:%s (%s: %s)",
                      host, port, type(exc).__name__, exc)
            return False

        ship_logger = logging.getLogger("night_sniffer.ship")
        ship_logger.setLevel(logging.INFO)
        ship_logger.addHandler(handler)
        # Load-bearing. night_sniffer_v3 calls logging.basicConfig(), so without
        # this every shipped frame is also printed to stdout by the root
        # handler — the whole capture, twice, on top of the existing per-frame
        # print().
        ship_logger.propagate = False

        # Keep the library's own logger audible: a refused connection or a
        # failed flush is reported through it, and that is exactly what this
        # test needs to see. It propagates to root, which is intended.
        logging.getLogger("logstash_async").setLevel(logging.WARNING)

        _ship_logger  = ship_logger
        _ship_handler = handler
        log.info("Logstash shipping enabled     : tcp://%s:%d (spool: %s)",
                 host, port, database_path or "memory")
        return True


def ship_row(fields: dict, message: str = "") -> None:
    """
    Queue one event. Never raises.

    Called from the single sniff thread, once per row already written to CSV.
    The counters are therefore single-writer and need no lock.
    """
    global _shipped, _ship_errors
    if _ship_logger is None:
        return
    try:
        _ship_logger.info(message, extra=fields)
        _shipped += 1
    except Exception as exc:
        _ship_errors += 1
        if _ship_errors <= MAX_SHIP_ERROR_LOGS:
            log.warning(
                "Event not queued (%s: %s)%s",
                type(exc).__name__, exc,
                " — further shipping errors will be counted, not logged"
                if _ship_errors == MAX_SHIP_ERROR_LOGS else "",
            )


def ship_stats() -> tuple[int, int]:
    """(events queued, events that could not be queued)."""
    return _shipped, _ship_errors


def close_shipper() -> None:
    """
    Flush and shut down the worker. Called once on the way out.

    close() blocks while the worker drains its queue. If Logstash is
    unreachable that wait is bounded by SHIP_SOCKET_TIMEOUT per attempt, so a
    dead sink delays exit rather than preventing it.
    """
    global _ship_logger, _ship_handler
    if _ship_handler is None:
        return
    log.info("Shipping totals               : %d queued, %d failed", *ship_stats())
    for step, fn in (("flush", _ship_handler.flush),
                     ("close", _ship_handler.close)):
        try:
            fn()
        except Exception as exc:
            log.warning("Shipper %s failed (%s: %s)", step, type(exc).__name__, exc)
    _ship_handler = None
    _ship_logger  = None
