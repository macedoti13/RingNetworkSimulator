import socket
from .packet import Packet
from .data_packet import DataPacket
from .token_packet import TokenPacket

class Machine:
    
    def __init__(self, ip: str, nickname: str, time_token: str, has_token: bool = False) -> None:
        self.ip = Machine.get_ip(ip)
        self.port = int(Machine.get_port(ip))
        self.nickname = nickname
        self.time_token = time_token
        self.has_token = has_token
        self.message_queue = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        if self.has_token == True:
            self.generate_token()
        
    def generate_token(self):
        self.token = TokenPacket()
        
    def add_packet_to_queue(self, packet: Packet):
        self.message_queue.append(packet)
        
    def send_packet(self, packet: Packet):
        self.socket.sendto(packet.header.encode(), (self.ip, self.port))
        
    def receive_packet(self):
        data, addr = self.socket.recvfrom(1024)  # buffer size is 1024 bytes
        type = Packet.get_packet_type(data.decode())
        if type == "1000":
            packet = TokenPacket()
        elif type == "2000":
            packet = DataPacket.create_header_from_string(data.decode())
            
        return self.process_packet(packet)
        
    @classmethod
    def get_ip(cls, ip: str):
        return ip.split(":")[0]
    
    @classmethod
    def get_port(cls, ip: str):
        return ip.split(":")[1]
    
    def close_socket(self):
        self.socket.close()
        
    def process_packet(self, packet: Packet):
        if packet.id == "1000":
            self.has_token = True
        elif packet.id == "2000":
            if packet.destination_name == self.nickname:
                # calcula crc
                # imprime log
                # altera o estado (ack para crc ok, nack para crc errado)
                # manda de volta 
                pass
            elif packet.origin_name == self.nickname:
                # ler estado 
                # se náo achou a maquina: tira msg da fila, passa o token, printa log 
                # se teve erro: printa log, passa o token e mantém a msg na fila
                # ack: printa log, passa o token e tira a msg da fila
                pass
            else:
                # passa para o próximo
                self.send_packet(packet)