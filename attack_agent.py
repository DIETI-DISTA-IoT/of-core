import time
import random
import threading


HEALTHY = "HEALTHY"
INFECTED = "INFECTED"


class AttackAgent():

    def __init__(self, container_manager, kwargs):
        self.container_manager = container_manager
        self.alive = False
        self.interval = kwargs.attack.automatic_attack_interval_secs
        self.thread = threading.Thread(target=self.attacking_thread)
        self.thread.daemon = True            



    def attacking_thread(self):
        while self.alive:
            healtty_vehicles = []

            for vehicle, status in self.container_manager.vehicle_status_dict.items():
                if status == HEALTHY:
                    healtty_vehicles.append(vehicle)

            if len(healtty_vehicles) == 0:
                continue
            else:
                random_vehicle = random.choice(healtty_vehicles)
                self.container_manager.start_attack_from_vehicle(random_vehicle, origin="AI")
            time.sleep(self.interval)


    def stop_all_attacks(self):
        for vehicle, status in self.container_manager.vehicle_status_dict.items():
            if status == INFECTED:
                self.container_manager.stop_attack_from_vehicle(vehicle, origin="AI")