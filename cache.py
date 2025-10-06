class MessageCache:
    def __init__(self, max_len):
        self.cache = {
            "all" : [], # Cache for real messages
            "anomalies" : [],  # Cache for anomaly messages
            "diagnostics" : [] # Cache for normal messages
        }
        self.max_len = max_len

    def add(self, cache_key, message):
        self.cache[cache_key].append(message)
        # Limit the cache size
        self.cache[cache_key] = self.cache[cache_key][-self.max_len:]
