from src.network.data_packet import DataPacket
from src.network.machine import Machine

pkg1 = DataPacket(origin_name="ace", destination_name="bob", 
                  error_control="maquinanaoexiste", message="oi bob 1")

pkg2 = DataPacket(origin_name="ace", destination_name="bob", 
                  error_control="maquinanaoexiste", message="oi bob 2")

pkg3 = DataPacket(origin_name="ace", destination_name="bob", 
                  error_control="maquinanaoexiste", message="oi bob 3")

ace = Machine.create_machine_from_file("machine_files/ace.txt", local_port=6001, local_ip="127.0.0.1")
ace.add_packet_to_queue(pkg1)
ace.add_packet_to_queue(pkg2)
ace.add_packet_to_queue(pkg3)
ace.start()