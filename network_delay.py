"""Network delay + jitter simulation — companion of ``packet_loss.py``.

Neither Kafka nor the offline in-process ``MessageBus`` adds any transit
latency to an accepted write, so a slow / jittery uplink is simulated on the
*sending* side, exactly like :class:`~OpenFAIR.packet_loss.PacketLossSimulator`
simulates a lossy one. For every outbound message the caller hands us a
``deliver`` callable (the real ``producer.produce(...)`` / ``bus.produce(...)``
call); we defer running it by a sampled latency of

    max(0, delay_mean_ms + N(0, jitter_std_ms))   milliseconds

on a private daemon worker thread, so the sender's own generation rate is not
throttled — a delayed link changes *when* a message arrives at the consumer,
not how fast the sender emits it (and, with jitter, messages may even be
reordered, just as on a real network).

Design notes kept deliberately close to ``PacketLossSimulator`` so the two
behave as a matched pair:

* One instance is meant to be shared across every message a single logical
  sender emits, so its counters reflect that sender's own send history.
* When neither delay nor jitter is configured the send runs *inline* on the
  caller's thread — behaviourally identical to a direct call, and the worker
  thread is never even started. This makes the simulator a zero-overhead no-op
  at the default (0, 0) setting, so it never perturbs a baseline run.
* ``stats()`` has the same shape/spirit as ``PacketLossSimulator.stats()`` so
  the dashboards / summaries can surface it the same way.
"""

import heapq
import random
import threading
import time


class NetworkDelaySimulator:
    """Client-side latency + jitter injector for one outbound message stream."""

    def __init__(self, delay_mean_ms=0.0, jitter_std_ms=0.0):
        self.delay_mean_ms = max(0.0, float(delay_mean_ms or 0.0))
        self.jitter_std_ms = max(0.0, float(jitter_std_ms or 0.0))
        self.sent = 0
        self.total_delay_ms = 0.0
        self.max_delay_ms = 0.0

        # Deferred-delivery scheduler (a single daemon worker draining a
        # time-ordered heap). Lazily created on the first delayed send.
        self._heap = []
        self._counter = 0
        self._cv = threading.Condition()
        self._worker = None
        self._closed = False

    @property
    def enabled(self):
        return self.delay_mean_ms > 0.0 or self.jitter_std_ms > 0.0

    def sample_delay_ms(self):
        """Draw one latency sample (ms), clamped at 0 (a negative jitter draw
        cannot make a packet arrive before it was sent)."""
        if not self.enabled:
            return 0.0
        d = self.delay_mean_ms
        if self.jitter_std_ms > 0.0:
            d += random.gauss(0.0, self.jitter_std_ms)
        return d if d > 0.0 else 0.0

    def send(self, deliver):
        """Push ``deliver`` (a zero-arg callable performing the real send)
        through the simulated link.

        Runs it after the sampled delay on the worker thread, or inline when no
        delay is configured. Accounting is done here, at enqueue time, so
        ``stats()`` reflects generation even for messages still in flight.
        """
        delay_ms = self.sample_delay_ms()
        self.sent += 1
        self.total_delay_ms += delay_ms
        if delay_ms > self.max_delay_ms:
            self.max_delay_ms = delay_ms

        if delay_ms <= 0.0:
            deliver()
            return

        self._ensure_worker()
        deliver_at = time.monotonic() + delay_ms / 1000.0
        with self._cv:
            heapq.heappush(self._heap, (deliver_at, self._counter, deliver))
            self._counter += 1
            self._cv.notify()

    def _ensure_worker(self):
        if self._worker is not None:
            return
        with self._cv:
            if self._worker is None and not self._closed:
                self._worker = threading.Thread(
                    target=self._run, name="network-delay", daemon=True)
                self._worker.start()

    def _run(self):
        while True:
            with self._cv:
                while not self._closed and not self._heap:
                    self._cv.wait()
                if self._closed and not self._heap:
                    return
                deliver_at, _, deliver = self._heap[0]
                wait = deliver_at - time.monotonic()
                if wait > 0:
                    # Not due yet — sleep until it is (or until a nearer message
                    # or close() wakes us).
                    self._cv.wait(timeout=wait)
                    continue
                heapq.heappop(self._heap)
            try:
                deliver()
            except Exception:
                # A send failure must not kill the delivery worker; the caller's
                # own try/except around the real produce handles logging.
                pass

    def close(self, drain=True):
        """Stop the worker thread. When ``drain`` is True (default) any messages
        still pending are delivered immediately on the caller's thread first, so
        nothing queued is silently lost at shutdown."""
        with self._cv:
            self._closed = True
            pending = [item[2] for item in self._heap] if drain else []
            self._heap = []
            self._cv.notify_all()
        for deliver in pending:
            try:
                deliver()
            except Exception:
                pass

    @property
    def observed_avg_delay_ms(self):
        return (self.total_delay_ms / self.sent) if self.sent else 0.0

    def stats(self):
        return {
            'delay_mean_ms': self.delay_mean_ms,
            'jitter_std_ms': self.jitter_std_ms,
            'messages_sent': self.sent,
            'avg_applied_delay_ms': self.observed_avg_delay_ms,
            'max_applied_delay_ms': self.max_delay_ms,
        }
