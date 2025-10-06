from confluent_kafka import Consumer, KafkaError
import time
import json
import threading

# Patterns to match different types of Kafka topics
topics_dict = {
    "anomalies": "^.*_anomalies$",  # Topics containing anomalies
    "normal_data": '^.*_normal_data$', # Topics with normal data
    "statistics" : '^.*_statistics$' # Topics with statistics data
}


class KafkaMessageConsumer:
    def __init__(self, parent, cfg):
        
        # controls the resubscription thread
        self.is_running = True
        self.current_topics = set()
        self.parent = parent
        self.retry_delay = 1

        configs = {'bootstrap.servers': cfg.dashboard.kafka_broker_url,  # Kafka broker URL
                        'group.id': cfg.dashboard.kafka_consumer_group_id,  # Consumer group for offset management
                        'auto.offset.reset': cfg.dashboard.kafka_auto_offset_reset,  # Start reading messages from the beginning if no offset is present
                        'allow.auto.create.topics': 'true'  # crucial for topic updating
                        }
        self.consumer = Consumer(configs)
        self.subscribe()
        self.topic_update()
        self.consuming_thread = threading.Thread(target=self.read_messages)
        self.consuming_thread.daemon = True
        
        # Thread for periodic resubscription
        self.resubscribe_interval_seconds = cfg.kafka_topic_update_interval_secs
        self.resubscription_thread = threading.Thread(target=self._periodic_topic_update)
        self.resubscription_thread.daemon = True


    def start(self):
        """
        Start both reading and resubscription threads
        """
        self.consuming_thread.start()
        self.resubscription_thread.start()


    def stop(self):
        """
        Gracefully stop the consumer and its threads
        """
        self.is_running = False
        self.consumer.close()
        
        # Wait for threads to finish
        self.consuming_thread.join()
        self.resubscription_thread.join()


    def _periodic_topic_update(self):
        """
        Periodically Kafka topics update.
        This method runs in a separate thread.
        """
        while self.is_running:
            try:
                # Wait for a certain interval before resubscribing
                time.sleep(self.resubscribe_interval_seconds)
                self.topic_update()
            except Exception as e:
                self.parent.logger.error(f"Error in periodic resubscription: {e}")


    def subscribe(self):
        try:
            self.consumer.subscribe(list(topics_dict.values()))
        except KafkaError as e:
            self.parent.logger.error(f"Error subscribing to topics: {e}")
            return None
        self.parent.logger.debug(f"(Re)Started consuming messages from topics: {list(topics_dict.values())}")
        
        
    def topic_update(self):
        available_topics = set(self.consumer.list_topics().topics.keys())
        new_topics = available_topics - self.current_topics
        self.current_topics = available_topics
        if len(new_topics) > 0:
            self.parent.logger.debug(f"New topics: {list(new_topics)}; Number of available topics: {len(self.current_topics)}")
            self.subscribe()


    def deserialize_message(self, msg):
        try:
            # Decode the message value from bytes to string and parse JSON
            message_value = json.loads(msg.value().decode('utf-8'))
            # self.parent.logger.debug(f"Received message from topic {msg.topic()}")
            return message_value
        except json.JSONDecodeError as e:
            self.parent.logger.error(f"Error deserializing message: {e}")
            return None
    

    def read_messages(self):
        try:
            while True:
                msg = self.consumer.poll(1.0)  # Poll for new messages with a timeout of 1 second
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        self.parent.logger.info(f"End of partition reached: {msg.error()}")
                    elif (msg.error().code() == KafkaError.UNKNOWN_TOPIC_OR_PART) and \
                        (msg.error().str().split(': ')[1] in list(topics_dict.values())):
                            self.parent.logger.info(f"No avilable vehicles yet. Please create some vehicles...")
                    else:
                        self.parent.logger.error(f"Consumer error: {msg.error()}")
                    continue

                # Deserialize the message and process it
                deserialized_data = self.deserialize_message(msg)
                if deserialized_data:
                    # self.parent.logger.debug(f"Processing message from topic {msg.topic()}")
                    self.parent.process_message_routine(msg.topic(), deserialized_data)
                else:
                    self.parent.logger.warning("Deserialized message is None")

                retry_delay = 1  # Reset retry delay on success
        except Exception as e:
            self.parent.logger.error(f"Error while reading message: {e}")
            self.parent.logger.info(f"Retrying in {self.retry_delay} seconds...")
            time.sleep(self.retry_delay)
            retry_delay = min(self.retry_delay * 2, 60)  # Exponential backoff, max 60 seconds
        finally:
            self.consumer.close()  # Close the Kafka consumer on exit