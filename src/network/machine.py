import time
import random
import socket
import threading
from .packet import Packet
from .data_packet import DataPacket
from .token_packet import TokenPacket

class Machine:
    def __init__(self, ip: str, nickname: str, time_token: str, has_token: bool = False, 
                 error_probability: float = 0.2, TIMEOUT_VALUE: int = 10, MINIMUM_TIME: int = 10) -> None:
        
        # IP and Port extraction
        self.ip, self.port = self._extract_ip_and_port(ip)
        
        # Basic attributes
        self.nickname = nickname
        self.time_token = time_token
        self.error_probability = error_probability
        self.TIMEOUT_VALUE = TIMEOUT_VALUE 
        self.MINIMUM_TIME = MINIMUM_TIME
        
        # Token control attributes
        self.has_token = has_token
        self.controls_token = self.has_token
        self.last_token_time = None
        
        # Networking setup
        self.message_queue = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Token generation if the machine starts with a token
        if self.has_token:
            self.generate_token()
        
        # Thread setup
        if self.controls_token:
            self.token_checker_thread = threading.Thread(target=self.check_token_status)
            self.token_checker_thread.start()
            
        self.terminate_event = threading.Event()
        self.listen_thread = threading.Thread(target=self.listen_for_packets)
        self.listen_thread.start()

    @staticmethod
    def _extract_ip_and_port(ip: str) -> tuple:
        """Extract IP and port from a given string."""
        ip_address, port = ip.split(":")
        return ip_address, int(port)
        
    def generate_token(self):
        self.token = TokenPacket()
        
    def add_packet_to_queue(self, packet: Packet):
        self.message_queue.append(packet)
        
    def send_packet(self, packet: Packet):
        if isinstance(packet, DataPacket):
            if random.random() < self.error_probability:
                packet.crc = packet.crc[:-1] + ('0' if packet.crc[-1] == '1' else '1')
                print(f"Erro introduzido no pacote com destino: {packet.destination_name}")
                
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
    def create_machine_from_file(cls, file_path: str):
        with open(file_path, 'r') as file:
            ip_and_port = file.readline().strip()
            nickname = file.readline().strip()
            time_token = file.readline().strip()
            has_token_str = file.readline().strip()
            has_token = True if has_token_str.lower() == "true" else False

        return cls(ip_and_port, nickname, time_token, has_token)
    
    def close_socket(self):
        self.socket.close()
        
    def run(self):
        if self.has_token == True:
            if len(self.message_queue) > 0:
                packet = self.message_queue[0]
                print("Segurando o token por " + self.time_token + " segundos...")
                time.sleep(self.time_token)  
                print("Mensagem enviada para: " + packet.destination_name)
                self.send_packet(packet)
            else:
                print("Nenhuma mensagem para enviar, passando token...")
                print("Segurando o token por " + self.time_token + " segundos...")
                time.sleep(self.time_token)  
                self.send_packet(self.token)
                self.has_token = False
        
    def process_packet(self, packet: Packet):
        if packet.id == "1000":
            self.last_token_time = time.time()
            if not self.has_token:
                self.has_token = True
                self.run()
            else:
                pass
            
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
                    self.send_packet(packet) # reenvia o pacote se houver erro
                elif packet.error_control == "maquinanaoexiste":
                    print("Máquina não existe: " + packet.message) # imprime log
                    self.message_queue.pop(0) # tira da fila
                
            elif packet.destination_name == "TODOS":
                calculated_crc = packet.calculate_crc() # calcula crc
                if calculated_crc == packet.crc:
                    print("Mensagem recebida: " + packet.message) # imprime log
                else:
                    print("Erro na mensagem: " + packet.message) # imprime log
                    self.send_packet(packet)
                    
                self.send_packet(self.token) # manda o token
                self.has_token = False # não tem mais o token
                
            else:
                # passa para o próximo
                self.send_packet(packet)

    def check_token_status(self):
        while True:
            time.sleep(1)  # Verifica o status do token a cada segundo (ajuste conforme necessário)
            
            if self.last_token_time is None:
                continue
            
            time_since_last_token = time.time() - self.last_token_time
            
            if time_since_last_token > self.TIMEOUT_VALUE:  # TIMEOUT_VALUE é o tempo máximo permitido sem ver o token
                print("Token não visto por muito tempo. Gerando novo token.")
                self.generate_token()
            
            elif time_since_last_token < self.MINIMUM_TIME:  # MINIMUM_TIME é o tempo mínimo esperado entre as passagens do token
                print("Token visto muito rapidamente. Retirando token da rede.")
                self.has_token = False

    def listen_for_packets(self):
        while not self.terminate_event.is_set():
            try:
                self.receive_packet()
            except Exception as e:
                print(f"Error while receiving packet: {e}")
            
    def stop_listening(self):
        self.terminate_event.set()
        self.listen_thread.join()
        self.close_socket()
