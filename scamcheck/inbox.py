"""One message in, one reply out: drop Twilio retries and merge a burst of messages into one investigation."""
import threading
import time
from collections import OrderedDict
from typing import Callable

Media = tuple[str, str]  # (url, content type)


class SeenMessages:
    """Twilio re-sends a webhook it thinks timed out. The same MessageSid must not start a second investigation."""

    def __init__(self, ttl: float = 3600, max_items: int = 10_000):
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()
        self.ttl, self.max_items = ttl, max_items

    def first_time(self, sid: str) -> bool:
        now = time.monotonic()
        with self._lock:
            while self._seen and (len(self._seen) >= self.max_items or now - next(iter(self._seen.values())) > self.ttl):
                self._seen.popitem(last=False)
            if sid in self._seen:
                return False
            self._seen[sid] = now
            return True


class Inbox:
    """Collects a burst of messages from one sender and hands them over together.

    People forward the scam, then type "is this real??" a few seconds later. Checked one by one, that costs twice,
    answers twice, and the second check has no idea what "this" is.
    """

    def __init__(self, on_batch: Callable[[str, list[str], list[Media]], None],
                 quiet_seconds: float = 8, max_wait_seconds: float = 25):
        self._on_batch = on_batch
        self.quiet_seconds = quiet_seconds        # wait this long after the latest message...
        self.max_wait_seconds = max_wait_seconds  # ...but never keep the first one waiting longer than this
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._generation = 0

    def add(self, sender: str, text: str, media: list[Media]) -> bool:
        """Queue a message. Returns True if it starts a new batch, i.e. deserves an acknowledgement."""
        with self._lock:
            batch = self._pending.get(sender)
            is_new = batch is None
            if is_new:
                batch = self._pending[sender] = {"texts": [], "media": [], "started": time.monotonic()}
            else:
                batch["timer"].cancel()
            if text:
                batch["texts"].append(text)
            batch["media"].extend(media)

            self._generation += 1
            batch["generation"] = self._generation
            waited = time.monotonic() - batch["started"]
            delay = max(0.0, min(self.quiet_seconds, self.max_wait_seconds - waited))
            batch["timer"] = threading.Timer(delay, self._flush, (sender, self._generation))
            batch["timer"].daemon = True
            batch["timer"].start()
            return is_new

    def drop(self, sender: str) -> None:
        """Forget anything queued (the person said 'reset')."""
        with self._lock:
            batch = self._pending.pop(sender, None)
            if batch:
                batch["timer"].cancel()

    def _flush(self, sender: str, generation: int) -> None:
        with self._lock:
            batch = self._pending.get(sender)
            # A timer that fired just as a new message arrived must not cut the newer batch short.
            if not batch or batch["generation"] != generation:
                return
            del self._pending[sender]
        self._on_batch(sender, batch["texts"], batch["media"])
