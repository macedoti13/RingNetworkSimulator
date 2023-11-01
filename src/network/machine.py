import time
import socket
import random
import logging
import threading
from .packet import Packet
from .data_packet import DataPacket
from .token_packet import TokenPacket

class Machine:
    
    def __init__(self, ip: str, nickname: str, time_token: str, has_token: bool = False, 
                 error_probability: float = 0.2, TIMEOUT_VALUE: int = 10, MINIMUM_TIME: int = 5) -> None:
        
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
            
        # Set up logging
        self.logger = logging.getLogger('MachineLogger')
        self.logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler('machine_log.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Thread setup
        if self.controls_token:
            self.token_checker_thread = threading.Thread(target=self.check_token_status)
            self.token_checker_thread.start()
            
        self.terminate_event = threading.Event()
        self.listen_thread = threading.Thread(target=self.listen_for_packets)
        self.listen_thread.start()


    @staticmethod
    def _extract_ip_and_port(ip: str) -> tuple:
        ip_address, port = ip.split(":")
        return ip_address, int(port)

        
    def generate_token(self):
        self.token = TokenPacket()

        
    def add_packet_to_queue(self, packet: Packet):
        self.message_queue.append(packet)

        
    def send_packet(self, packet: Packet):
        if isinstance(packet, DataPacket) and random.random() < self.error_probability:
            packet.crc = packet.crc[:-1] + ('0' if packet.crc[-1] == '1' else '1')
            self.logger.debug(f"Erro introduzido no pacote com destino: {packet.destination_name}")
        self.socket.sendto(packet.header.encode(), (self.ip, self.port))

        
    def receive_packet(self):
        data, _ = self.socket.recvfrom(1024)
        packet_type = Packet.get_packet_type(data.decode())
        packet = TokenPacket() if packet_type == "1000" else DataPacket.create_header_from_string(data.decode())
        return self.process_packet(packet)

            
    @classmethod
    def create_machine_from_file(cls, file_path: str):
        with open(file_path, 'r') as file:
            ip_and_port, nickname, time_token, has_token_str = [file.readline().strip() for _ in range(4)]
            has_token = has_token_str.lower() == "true"
        return cls(ip_and_port, nickname, time_token, has_token)

    
    def close_socket(self):
        self.socket.close()

        
    def run(self):
        if self.has_token == True:
            if len(self.message_queue) > 0:
                packet = self.message_queue[0]
                self.logger.debug(f"Segurando o token por {self.time_token} segundos...")
                time.sleep(self.time_token)  
                self.logger.debug(f"Enviando mensagem para: {packet.destination_name}")
                self.send_packet(packet)
            else:
                self.logger.debug(f"Nenhuma mensagem para enviar, segurando o token por {self.time_token} segundos...")
                time.sleep(self.time_token)  
                self.logger.debug(f"Passando o token...")
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
                    self.logger.debug(f"Mensagem recebida: {packet.message}")
                else:
                    packet.error_control = "NACK" # altera o estado
                    self.logger.debug(f"Erro na mensagem: {packet.message}")
                self.send_packet(packet) # manda de volta 
                
            elif packet.origin_name == self.nickname:
                if packet.error_control == "ACK":
                    self.logger.debug(f"Mensagem enviada: {packet.message}")
                    self.message_queue.pop(0) # tira da fila
                elif packet.error_control == "NACK":
                    self.logger.debug(f"Erro na mensagem: {packet.message}")
                    self.send_packet(packet) # reenvia o pacote se houver erro
                elif packet.error_control == "maquinanaoexiste":
                    self.logger.debug(f"Máquina não existe: {packet.message}")
                    self.message_queue.pop(0) # tira da fila
                
            elif packet.destination_name == "TODOS":
                calculated_crc = packet.calculate_crc() # calcula crc
                if calculated_crc == packet.crc:
                    self.logger.debug(f"Mensagem recebida: {packet.message}")
                else:
                    self.logger.debug(f"Erro na mensagem: {packet.message}")
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
                self.logger.debug(f"Token não visto por muito tempo. Gerando novo token.")
                self.generate_token()
            
            elif time_since_last_token < self.MINIMUM_TIME:  # MINIMUM_TIME é o tempo mínimo esperado entre as passagens do token
                self.logger.debug(f"Token visto muito rapidamente. Retirando token da rede.")
                self.has_token = False


    def listen_for_packets(self):
        while not self.terminate_event.is_set():
            try:
                self.receive_packet()
            except Exception as e:
                self.logger.debug(f"Erro ao receber packet: {e}")

            
    def stop_listening(self):
        self.terminate_event.set()
        self.listen_thread.join()
        self.close_socket()


    def user_interaction(self):
        while not self.terminate_event.is_set():
            print("\nOptions:")
            print("1. Add a new packet to the queue")
            print("2. Shutdown the machine")
            print("3. Print current message queue")
            choice = input("Enter your choice: ")

            if choice == "1":
                print("What type of packet do you want to send? Either enter token (1000) or data (2000).")
                type = input("Enter packet type: ")
                if type == "2000":
                    destination_name = input("Enter destination name: ")
                    message = input("Enter message: ")
                    new_packet = DataPacket(destination_name=destination_name, message=message)
                elif type == "1000":
                    new_packet = TokenPacket()
                else:
                    print("Invalid packet type. Please try again.")
                
                self.add_packet_to_queue(new_packet)
                print(f"Packet added to the queue for {destination_name} with message: {message}")

            elif choice == "2":
                print("Shutting down the machine...")
                self.terminate_event.set()
                self.stop_listening()
                # If you have other threads, make sure to join or terminate them properly here
                if self.controls_token:
                    self.token_checker_thread.join()
                self.listen_thread.join()
                print("Machine shutdown complete.")
                break

            elif choice == "3":
                print("Current message queue:")
                for packet in self.message_queue:
                    print(packet.message)  # Adjust based on your packet structure

            else:
                print("Invalid choice. Please try again.")
