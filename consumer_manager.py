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


    def update_consumer_configs(self, default_consumer_config: dict, vehicles: list) -> None:
        """Rebuild per-consumer configs from an updated default, preserving per-vehicle overrides.

        Replicates the __init__ layering: default_consumer_config is the new base,
        then each vehicle's individual overrides are re-applied on top.
        kafka_topic_update_interval_secs is preserved from the original default.
        Only vehicles already known to this manager are updated.
        """
        new_default = dict(default_consumer_config)
        new_default["kafka_topic_update_interval_secs"] = self.default_consumer_config.get(
            "kafka_topic_update_interval_secs", new_default.get("kafka_topic_update_interval_secs")
        )
        self.default_consumer_config = new_default
        for vehicle in vehicles:
            if isinstance(vehicle, str):
                vehicle_name = vehicle
                per_vehicle_overrides = {}
            else:
                vehicle_name = list(vehicle.keys())[0]
                per_vehicle_overrides = dict(vehicle[vehicle_name])
            if vehicle_name not in self.consumer_configs:
                continue
            cfg = dict(new_default)
            cfg.update(per_vehicle_overrides)
            self.consumer_configs[vehicle_name] = cfg


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

            cfg_payload = consumer_config.copy()
            cfg_payload.update(self.cfg.anomaly_detection)
            # Build config payload
            cfg_payload.update({
                'logging_level': self.logging_level,
                'model_saving_path': vehicle_name + '_' + self.override + '_model.pth',
                'probe_metrics': list(map(str, self.cfg.security_manager.probe_metrics)),
                'mode': str(self.cfg.mode),
                'manager_port': int(self.cfg.dashboard.port),
                'manager_ip': self.containers_ips.get('dashboard'),
                'true_positive_reward': float(self.cfg.security_manager.true_positive_reward),
                'false_positive_reward': float(self.cfg.security_manager.false_positive_reward),
                'true_negative_reward': float(self.cfg.security_manager.true_negative_reward),
                'false_negative_reward': float(self.cfg.security_manager.false_negative_reward)
            })

            if self.cfg.security_manager.mitigation:
                cfg_payload['mitigation'] = True
            if self.cfg.dashboard.proxy:
                cfg_payload['no_proxy_host'] = True


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

        try:
            vehicle_name = consumer_name.split("_")[0]
            container_ip = self.containers_ips[vehicle_name+"_consumer"]
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