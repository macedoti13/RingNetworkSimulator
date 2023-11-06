from src.network.data_packet import DataPacket
from src.network.machine import Machine

pkg1 = DataPacket(origin_name="bob", destination_name="ace", 
                  error_control="maquinanaoexiste", message="oi ace 1")

pkg2 = DataPacket(origin_name="bob", destination_name="ace", 
                  error_control="maquinanaoexiste", message="oi ace 2")

pkg3 = DataPacket(origin_name="bob", destination_name="ace", 
                  error_control="maquinanaoexiste", message="oi ace 3")

bob = Machine.create_machine_from_file("machine_files/bob.txt", local_port=6000, local_ip="127.0.0.1")
bob.add_packet_to_queue(pkg1)
bob.add_packet_to_queue(pkg2)
bob.add_packet_to_queue(pkg3)
bob.start()
