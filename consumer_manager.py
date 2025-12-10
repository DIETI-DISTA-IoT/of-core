import logging
from omegaconf import DictConfig
import requests
import time

class ConsumerManager:

    def __init__(self, cfg, consumers, containers_ips, CONSUMER_COMMAND="python consume.py"):
        self.consumers = consumers
        self.threads = {}
        self.consumer_command = CONSUMER_COMMAND
        self.containers_ips = containers_ips
        self.logger = logging.getLogger("CONSUMER_MANAGER")
        self.cfg = cfg
        self.logging_level = cfg.logging_level.upper()
        self.logger.setLevel(self.logging_level)
        self.default_consumer_config = dict(cfg.default_consumer_config)
        self.default_consumer_config["kafka_topic_update_interval_secs"] = cfg.kafka_topic_update_interval_secs
        self.consumer_configs = {}
        self.override = cfg.override

        # HTTP session configured to ignore system proxy settings for internal Docker IPs
        self.http = requests.Session()
        # Do not use environment proxies (prevents corporate proxy from intercepting 172.* calls)
        self.http.trust_env = False


        for vehicle in cfg.vehicles:
            if type(vehicle) == str:
                vehicle_name = vehicle
            else:
                vehicle_name = list(vehicle.keys())[0]
            self.consumer_configs[vehicle_name] = self.default_consumer_config.copy()
            if type(vehicle) == DictConfig:
                self.consumer_configs[vehicle_name].update(vehicle[vehicle_name])
            if self.consumer_configs[vehicle_name]["anomaly_classes"] == "all":
                self.consumer_configs[vehicle_name]["anomaly_classes"] = list(range(1, 19))
            if self.consumer_configs[vehicle_name]["diagnostics_classes"] == "all":
                self.consumer_configs[vehicle_name]["diagnostics_classes"] = list(range(1, 15))


    def start_all_consumers(self):
        results = []
        for consumer_name, consumer in self.consumers.items():
            results.append(self.start_consumer(consumer_name, consumer))
        return "All consumers started!", results
    
    def _wait_for_health(self, api_url, overall_timeout_seconds=60, poll_interval_seconds=2):
        """Poll the CONSUMER /health endpoint until healthy or timeout.
        Returns True if healthy, False otherwise.
        """
        logger = logging.getLogger("CONSUMER_MANAGER")
        deadline = time.time() + overall_timeout_seconds
        while time.time() < deadline:
            try:
                resp = self.http.get(f"{api_url}/health", timeout=5)
                if resp.ok:
                    # Validate it's the consumer health, not dashboard's
                    try:
                        data = resp.json()
                        # consumer health has keys like 'running' or 'config_loaded' or 'vehicle'
                        if isinstance(data, dict) and ("running" in data or "config_loaded" in data or "vehicle" in data):
                            logger.info(f"Health check passed for {api_url}: {data}")
                            return True
                        else:
                            logger.debug(f"Health check response doesn't look like consumer API: {data}")
                    except Exception as e:
                        logger.debug(f"Failed to parse health response from {api_url}: {e}")
                else:
                    logger.debug(f"Health check failed with status {resp.status_code} for {api_url}")
            except requests.exceptions.RequestException as e:
                logger.debug(f"Health check request failed for {api_url}: {e}")
            time.sleep(poll_interval_seconds)
        logger.error(f"Health check timed out or not consumer API for {api_url}")
        return False
    

    def start_consumer(self, consumer_name, consumer_container):
        try:
            vehicle_name = consumer_name.split("_")[0]
            consumer_config = self.consumer_configs[vehicle_name]
            container_ip = self.containers_ips[vehicle_name+"_consumer"]
            hostname_url = f"http://{consumer_name}:5000"
            ip_url = f"http://{container_ip}:5000"


            # Pick the first URL whose health endpoint looks like the producer API (not the dashboard)
            api_url = None
            for candidate in (hostname_url, ip_url):
                if self._wait_for_health(candidate, overall_timeout_seconds=20):
                    api_url = candidate
                    break
            if not api_url:
                return f"Failed to start consumer {consumer_name}: API not healthy"

            # Build config payload
            cfg_payload = {
                'kafka_broker': consumer_config['kafka_broker'],
                'buffer_size': consumer_config['buffer_size'],
                'batch_size': consumer_config['batch_size'],
                'logging_level': self.logging_level,
                'weights_push_freq_seconds': consumer_config['weights_push_freq_seconds'],
                'weights_pull_freq_seconds': consumer_config['weights_pull_freq_seconds'],
                'kafka_topic_update_interval_secs': consumer_config['kafka_topic_update_interval_secs'],
                'learning_rate': consumer_config['learning_rate'],
                'epoch_size': consumer_config['epoch_size'],
                'input_dim': self.cfg.anomaly_detection.input_dim,
                'output_dim': self.cfg.anomaly_detection.output_dim,
                'h_dim': self.cfg.anomaly_detection.h_dim,
                'num_layers': self.cfg.anomaly_detection.num_layers,
                'dropout': consumer_config['dropout'],
                'optimizer': consumer_config['optimizer'],
                'training_freq_seconds': consumer_config['training_freq_seconds'],
                'save_model_freq_epochs': consumer_config['save_model_freq_epochs'],
                'model_saving_path': vehicle_name + '_' + self.override + '_model.pth',
                'probe_metrics': list(map(str, self.cfg.security_manager.probe_metrics)),
                'mode': str(self.cfg.mode),
                'manager_port': int(self.cfg.dashboard.port),
                'true_positive_reward': float(self.cfg.security_manager.true_positive_reward),
                'false_positive_reward': float(self.cfg.security_manager.false_positive_reward),
                'true_negative_reward': float(self.cfg.security_manager.true_negative_reward),
                'false_negative_reward': float(self.cfg.security_manager.false_negative_reward)
            }

            if self.cfg.security_manager.mitigation:
                cfg_payload['mitigation'] = True
            if self.cfg.dashboard.proxy:
                cfg_payload['no_proxy_host'] = True
            if self.cfg.anomaly_detection.layer_norm:
                cfg_payload['layer_norm'] = True


            config_response = self.http.post(
                f"{api_url}/configure",
                json=cfg_payload,
                timeout=30
            )
            config_response.raise_for_status()


            start_response = self.http.post(
                f"{api_url}/start",
                json={},
                timeout=30
            )
            start_response.raise_for_status()

            status_response = self.http.get(f"{api_url}/status", timeout=10)
            status_response.raise_for_status()

            self.logger.info(f"Consumer {consumer_name} started successfully")
            return f"Consumer {consumer_name} started successfully"
        except Exception as e:
            msg = f"Failed to start consumer {consumer_name}: {e}"
            self.logger.error(msg)
            return msg


    def stop_consumer(self, consumer_name):
        container = self.consumers[consumer_name]
        try:
            container_ip = container.attrs['NetworkSettings']['IPAddress']
            hostname_url = f"http://{consumer_name}:5000/stop"
            tried = []
            # Try hostname first
            try:
                tried.append(hostname_url)
                r = requests.post(hostname_url, json={}, timeout=20)
                r.raise_for_status()
                self.logger.info(f"Stopped consumer {consumer_name}")
                return
            except Exception:
                pass

            # Fallback to IP if available
            if container_ip:
                ip_url = f"http://{container_ip}:5000/stop"
                tried.append(ip_url)
                r = requests.post(ip_url, json={}, timeout=20)
                r.raise_for_status()
                self.logger.info(f"Stopped consumer {consumer_name}")
                return

            raise RuntimeError(f"Could not reach consumer stop endpoint. Tried: {', '.join(tried)}")
        except Exception as e:
            self.logger.info(f"Error stopping {consumer_name}: {e}")


    def stop_all_consumers(self):
        for consumer_name in self.consumers:
            self.stop_consumer(consumer_name)