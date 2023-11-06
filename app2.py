from src.network.machine import Machine
from src.network.data_packet import DataPacket

pkg1 = DataPacket(origin_name="Jake", destination_name="Bob", 
                  error_control="maquinanaoexiste", message="salve")

pkg2 = DataPacket(origin_name="Jake", destination_name="Bob", 
                  error_control="maquinanaoexiste", message="como vai?")

pkg3 = DataPacket(origin_name="Jake", destination_name="Bob", 
                  error_control="maquinanaoexiste", message="blz")


machine2 = Machine.create_machine_from_file("machine2.txt", local_port=6001)
machine2.add_packet_to_queue(pkg1)
machine2.add_packet_to_queue(pkg2)
machine2.add_packet_to_queue(pkg3)
machine2.start()