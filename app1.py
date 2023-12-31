from src.network.machine import Machine

bob = Machine.create_machine_from_file("machine_files/bob.txt", 
                                       local_port=6000, 
                                       local_ip="127.0.0.1",
                                       TIMEOUT_VALUE=12, 
                                       MINIMUM_TIME=1, 
                                       error_probability=0.5)
bob.start()
