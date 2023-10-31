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
        # inserir erro no pacote com probabilidade
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
        
    def run(self):
        if self.has_token == True:
            if len(self.message_queue) > 0:
                packet = self.message_queue[0]
                self.send_packet(packet)
            else:
                self.send_packet(self.token)
                self.has_token = False
        
    def process_packet(self, packet: Packet):
        if packet.id == "1000":
            self.has_token = True
            self.run() # roda o algoritmo para ver se tem que mandar alguma coisa
            
        elif packet.id == "2000":
            
            if packet.destination_name == self.nickname:
                calculated_crc = packet.calculate_crc() # calcula crc
                if calculated_crc == packet.crc:
                    packet.error_control = "ACK" # altera o estado
                    print("Mensagem recebida: " + packet.message) # imprime log
                else:
                    packet.error_control = "NACK" # altera o estado
                    print("Erro na mensagem: " + packet.message) # imprime log
                self.send_packet(packet) # manda de volta 
            
            elif packet.origin_name == self.nickname:
                if packet.error_control == "ACK":
                    print("Mensagem enviada: " + packet.message) # imprime log
                    self.message_queue.pop(0) # tira da fila
                elif packet.error_control == "NACK":
                    print("Erro na mensagem: " + packet.message) # imprime log
                elif packet.error_control == "maquinanaoexiste":
                    print("Máquina não existe: " + packet.message) # imprime log
                    self.message_queue.pop(0) # tira da fila
                    
                self.send_packet(self.token) # manda o token
                self.has_token = False # não tem mais o token
                
            else:
                # passa para o próximo
                self.send_packet(packet)
