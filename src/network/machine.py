import sys
import time
import socket
import random
import logging
import datetime
import threading
from .packet import Packet
from .data_packet import DataPacket
from .token_packet import TokenPacket
from .file_handler import FlushingFileHandler


class Machine:
    
    def __init__(self, ip: str, nickname: str, time_token: str, has_token: bool = False, 
                 error_probability: float = 0.2, TIMEOUT_VALUE: int = 100, MINIMUM_TIME: int = 2, 
                 local_ip: str = "127.0.0.1", local_port: int = 6000) -> None:
        
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
        self.last_token_time = None if not has_token else datetime.datetime.now()
        self.controls_token = self.has_token
        
        # Networking setup
        self.message_queue = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_ip, local_port))
        
        # Token generation if the machine starts with a token
        if self.has_token:
            self.generate_token()
            
        # Set up logging
        self.logger = logging.getLogger('MachineLogger')
        self.logger.setLevel(logging.DEBUG)
        fh = FlushingFileHandler(f"logs/{self.nickname}_log.log", "a")
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        
        
    
    def start(self):
        # Define the terminate_event first
        self.terminate_event = threading.Event()

        if self.controls_token:
            self.token_checker_thread = threading.Thread(target=self.check_token_status)
            self.token_checker_thread.start()

        self.listen_thread = threading.Thread(target=self.listen_for_packets)
        self.listen_thread.start()

        # Adicionando a thread para user_interaction
        self.user_interaction_thread = threading.Thread(target=self.user_interaction)
        self.user_interaction_thread.start()
        
        self.logger.debug(f"Máquina {self.nickname} iniciada.")
        self.logger.debug('-'*50+'\n')
        
        if self.has_token:
            self.logger.debug(f"Máquina {self.nickname} possui o token. Dormindo por {self.time_token} segundos...\n")
            time.sleep(int(self.time_token))
            self.send_packet(self.token)
            self.has_token = False



    @staticmethod
    def _extract_ip_and_port(ip: str) -> tuple:
        ip_address, port = ip.split(":")
        return ip_address, int(port)


        
    def generate_token(self):
        self.token = TokenPacket()
        self.has_token = True

        
        
    def add_packet_to_queue(self, packet: Packet):
        self.message_queue.append(packet)


        
    def send_packet(self, packet: Packet, add_error_chance: bool = False):
        
        if isinstance(packet, DataPacket):
            self.logger.debug("Enviando pacote de dados...")
        elif isinstance(packet, TokenPacket):
            self.logger.debug("Enviando token...")
            
        if isinstance(packet, DataPacket) and random.random() < self.error_probability:
            if add_error_chance == True:
                packet.crc = packet.crc[:-1] + ('0' if packet.crc[-1] == '1' else '1')
                self.logger.debug(f"Erro introduzido no pacote com destino: {packet.destination_name}")
        self.socket.sendto(packet.header.encode(), (self.ip, self.port))
        
        if isinstance(packet, DataPacket):
            self.logger.debug("Pacote de dados enviado.")
            self.logger.debug('-'*50+'\n')
        elif isinstance(packet, TokenPacket):
            self.logger.debug("Token enviado.")
            self.logger.debug('-'*50+'\n')


        
    def receive_packet(self):
        data, _ = self.socket.recvfrom(1024)
        packet_type = Packet.get_packet_type(data.decode())
        packet = TokenPacket() if packet_type == "1000" else DataPacket.create_header_from_string(data.decode())
        self.logger.debug("Pacote recebido. Iniciando processamento...\n")
        return self.process_packet(packet)

         
            
    @classmethod
    def create_machine_from_file(cls, file_path: str, local_ip: str = "127.0.0.1", local_port: int = 6000):
        with open(file_path, 'r') as file:
            ip_and_port, nickname, time_token, has_token_str = [file.readline().strip() for _ in range(4)]
            has_token = has_token_str.lower() == "true"
        return cls(ip_and_port, nickname, time_token, has_token, local_ip=local_ip, local_port=local_port)

    
    
    def close_socket(self):
        self.socket.close()

        
        
    def run(self):
        if self.has_token == True:
            if len(self.message_queue) > 0:
                self.logger.debug(f"segurando o token por {self.time_token} segundos...")
                time.sleep(int(self.time_token))  
                self.logger.debug("enviando mensagem...")
                packet = self.message_queue[0]
                self.send_packet(packet, add_error_chance=True)
            else:
                self.logger.debug(f"Nenhuma mensagem para enviar, segurando o token por {self.time_token} segundos...\n")
                self.logger.debug('-'*50+'\n')
                time.sleep(int(self.time_token))  
                self.send_packet(self.token)
                self.has_token = False


        
    def process_packet(self, packet: Packet):

        if packet.id == "1000":
            self.last_token_time = datetime.datetime.now()
            self.logger.debug("Token recebido.")
            if not self.has_token:
                self.has_token = True
                self.token = packet
                self.run()
            else:
                pass
            
        elif packet.id == "2000":
            if packet.destination_name == self.nickname:
                self.logger.debug("Pacote para mim!")
                calculated_crc = packet.calculate_crc() # calcula crc
                if calculated_crc == packet.crc:
                    packet.error_control = "ACK" # altera o estado
                    self.logger.debug(f"Mensagem recebida com sucesso! Conteúdo: {packet.message}")
                else:
                    packet.error_control = "NACK" # altera o estado
                    self.logger.debug(f"Erro na mensagem recebida. CRC divergente!")
                
                self.logger.debug("Enviando pacote de volta...\n")
                self.logger.debug('-'*50+'\n')
                packet.header = packet.create_header() # cria o header
                self.send_packet(packet) # manda de volta 
                
            elif packet.origin_name == self.nickname:
                
                self.logger.debug("Pacote de volta!")
                self.logger.debug(f"Mensagem contida no pacote: {packet.message}\n")
                
                if packet.error_control == "ACK":

                    self.logger.debug(f"Mensagem enviada foi recebida pelo destino!")
                    self.message_queue.pop(0) # tira da fila
                    
                    self.logger.debug("pacote removido da fila")
                    self.logger.debug("passando o token...")
                    
                    self.send_packet(self.token) # manda o token
                    self.has_token = False # não tem mais o token
                    
                elif packet.error_control == "NACK":
                    self.logger.debug("Ocorreu um erro na mensagem")
                    self.send_packet(packet) # reenvia o pacote se houver erro
                    
                elif packet.error_control == "maquinanaoexiste":
                    self.logger.debug("Máquina não foi encontrada na rede.")

                    self.message_queue.pop(0) # tira da fila
                    self.logger.debug("Enviando o token...")
                    
                    self.send_packet(self.token) # manda o token
                    self.has_token = False # não tem mais o token
                
            elif packet.destination_name == "TODOS":
                self.logger.debug("Pacote para todos!")
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
        while not self.terminate_event.is_set():  # Check for the terminate_event here
            time.sleep(int(self.time_token))
            
            if self.last_token_time is None:
                continue
            
            time_since_last_token = (datetime.datetime.now() - self.last_token_time).total_seconds()
            
            if time_since_last_token > self.TIMEOUT_VALUE:  # TIMEOUT_VALUE é o tempo máximo permitido sem ver o token
                
                self.logger.debug('\n'+'-'*50+'\n')
                self.logger.debug(f"Token não visto por muito tempo. Gerando novo token.")
                self.logger.debug('\n'+'-'*50+'\n')
                
                self.generate_token()
                self.last_token_time = datetime.datetime.now()
                pass

            elif time_since_last_token < self.MINIMUM_TIME:  # MINIMUM_TIME é o tempo mínimo esperado entre as passagens do token
                
                self.logger.debug('\n'+'-'*50+'\n')
                self.logger.debug(f"Token visto muito rapidamente. Retirando token da rede.")
                self.logger.debug('\n'+'-'*50+'\n')
                
                self.has_token = False
                pass



    def listen_for_packets(self):
        while not self.terminate_event.is_set():
            try:
                self.receive_packet()
            except Exception as e:
                self.logger.debug(f"Erro ao receber packet: {e}")

            
            
    def stop_listening(self):
        # Join the listening thread
        try:
            self.listen_thread.join(timeout=5)
        except Exception as e:
            self.logger.debug(f"Error joining listen_thread: {e}")

        # If there's a token checker thread, join it too
        if self.controls_token:
            try:
                self.token_checker_thread.join(timeout=5)
            except Exception as e:
                self.logger.debug(f"Error joining token_checker_thread: {e}")

        # Close the socket
        self.close_socket()



    def user_interaction(self):
        while not self.terminate_event.is_set():
            print("\nOpções:")
            print("1. Adicionar um novo pacote à fila")
            print("2. Desligar a máquina")
            print("3. Mostrar fila de mensagens atual")
            choice = input("Digite sua escolha: ")

            if choice == "1":
                print("Que tipo de pacote você deseja enviar? Digite token (1000) ou dados (2000).")
                tipo = input("Digite o tipo do pacote: ")
                if tipo == "2000":
                    destination_name = input("Digite o nome do destino: ")
                    message = input("Digite a mensagem: ")
                    new_packet = DataPacket(origin_name=self.nickname, destination_name=destination_name, error_control="maquinanaoexiste", message=message)
                    print(f"Pacote adicionado à fila para {destination_name} com a mensagem: {message}")
                elif tipo == "1000":
                    new_packet = TokenPacket()
                    print(f"Token adicionado à fila.")
                else:
                    print("Tipo de pacote inválido. Por favor, tente novamente.")
                
                self.add_packet_to_queue(new_packet)

            elif choice == "2":
                print("Desligando a máquina...")
                self.terminate_event.set()
                self.stop_listening()
                print("Desligamento da máquina concluído.")
                sys.exit(0)

            elif choice == "3":
                print("Fila de mensagens atual:")
                for packet in self.message_queue:
                    print(packet.message) 

            else:
                print("Escolha inválida. Por favor, tente novamente.")
