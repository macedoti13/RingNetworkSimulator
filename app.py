from src.network.machine import Machine
from src.network.data_packet import DataPacket

pkg1 = DataPacket(origin_name="Bob", destination_name="Jake", 
                  error_control="maquinanaoexiste", message="oi")

pkg2 = DataPacket(origin_name="Bob", destination_name="Jake", 
                  error_control="maquinanaoexiste", message="me responde!!!")

pkg3 = DataPacket(origin_name="Bob", destination_name="Jake", 
                  error_control="maquinanaoexiste", message="te odeio")


machine = Machine.create_machine_from_file("machine.txt", local_port=6000)
machine.add_packet_to_queue(pkg1)
machine.add_packet_to_queue(pkg2)
machine.add_packet_to_queue(pkg3)
machine.start()