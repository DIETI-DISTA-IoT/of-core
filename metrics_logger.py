import logging

class MetricsLogger:
    def __init__(self, cfg):
        # Configure logging for detailed output
        self.logger = logging.getLogger("METRICS_LOGGER")
        # Set the log level
        self.logger.setLevel(cfg.logging_level.upper())

        self.metrics = {}


    def add(self, key, value):
        self.metrics[key] = value


    def process_stat_message(self, msg):
        """
        Update vehicle statistics based on a received statistics message.

        Args:
            msg (dict): The statistics message data.
        """
        try:
            vehicle_name=msg.get("vehicle_name", "unknown_vehicle")
            self.logger.debug(f"Processing statistics for vehicle: {vehicle_name}")

            # Initialize statistics for the vehicle if not already present
            if vehicle_name not in self.metrics:
                self.metrics[vehicle_name] = {'total_messages': 0, 'anomalies_messages': 0, 'normal_messages': 0}

            # Update statistics for the vehicle
            for key in self.metrics[vehicle_name]:
                previous_value = self.metrics[vehicle_name][key]
                increment = msg.get(key, 0)
                self.metrics[vehicle_name][key] += increment
                # self.logger.debug(f"Updated {key} for {vehicle_name}: {previous_value} -> {self.metrics[vehicle_name][key]}")

        except Exception as e:
            self.logger.error(f"Error while processing statistics: {e}")