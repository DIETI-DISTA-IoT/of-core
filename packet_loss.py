import random


class PacketLossSimulator:
    """Client-side packet-loss injector for one outbound message stream.

    Kafka (and the offline in-process MessageBus that stands in for it) never
    drops an accepted write, so lossy-network conditions are simulated on the
    sending side: before a message would be handed to the producer, a
    Bernoulli(packet_loss_rate) draw decides whether it is silently discarded
    instead. One instance is meant to be shared across every message a single
    logical sender emits (a vehicle's producer, a vehicle's weights/statistics
    reporter, the FL manager's global weights/metrics reporter), so its
    counters reflect that sender's own send/drop history.
    """

    def __init__(self, packet_loss_rate=0.0):
        self.packet_loss_rate = max(0.0, min(1.0, float(packet_loss_rate or 0.0)))
        self.sent = 0
        self.dropped = 0

    def should_drop(self):
        """Return True if the caller should discard the message instead of sending it."""
        if self.packet_loss_rate <= 0.0:
            self.sent += 1
            return False
        if random.random() < self.packet_loss_rate:
            self.dropped += 1
            return True
        self.sent += 1
        return False

    @property
    def total(self):
        return self.sent + self.dropped

    @property
    def observed_loss_rate(self):
        return (self.dropped / self.total) if self.total else 0.0

    def stats(self):
        return {
            'packet_loss_rate': self.packet_loss_rate,
            'packets_sent': self.sent,
            'packets_dropped': self.dropped,
            'observed_loss_rate': self.observed_loss_rate,
        }
