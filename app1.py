from src.network.machine import Machine

bob = Machine.create_machine_from_file("machine_files/bob.txt", 
                                       local_port=6000, 
                                       local_ip="127.0.0.1",
                                       TIMEOUT_VALUE=10, 
                                       MINIMUM_TIME=4, 
                                       error_probability=0.4)
bob.start()
