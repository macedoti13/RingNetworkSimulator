import sys
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
                 error_probability: float = 0.2, TIMEOUT_VALUE: int = 100, MINIMUM_TIME: int = 2, local_port: int = 6000) -> None:
        
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
        self.last_token_time = None if not has_token else time.time()
        self.controls_token = self.has_token
        
        # Networking setup
        self.message_queue = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', local_port))
        
        # Token generation if the machine starts with a token
        if self.has_token:
            self.generate_token()
            
        # Set up logging
        self.logger = logging.getLogger('MachineLogger')
        self.logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler(f'{self.nickname}_log.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
    
    def start(self):
        # Define the terminate_event first
        self.terminate_event = threading.Event()

        if self.controls_token:
            self.token_checker_thread = threading.Thread(target=self.check_token_status)
            self.token_checker_thread.start()

        self.listen_thread = threading.Thread(target=self.listen_for_packets)
        self.listen_thread.start()

        # Adicionando a thread para user_interaction
        #self.user_interaction_thread = threading.Thread(target=self.user_interaction)
        #self.user_interaction_thread.start()
        print(f"\nMáquina {self.nickname} iniciada.")
        print('-'*50+'\n')
        
        if self.has_token:
            print("Eu possuo o token, dormindo por {} segundos...".format(self.time_token))
            time.sleep(int(self.time_token))
            self.send_packet(self.token)
            self.has_token = False


    @staticmethod
    def _extract_ip_and_port(ip: str) -> tuple:
        ip_address, port = ip.split(":")
        return ip_address, int(port)

        
    def generate_token(self):
        print("novo token gerado")
        self.token = TokenPacket()
        self.has_token = True

        
    def add_packet_to_queue(self, packet: Packet):
        self.message_queue.append(packet)

        
    def send_packet(self, packet: Packet, add_error_chance: bool = False):
        print()
        if isinstance(packet, DataPacket):
            print("Enviando pacote de dados...")
        elif isinstance(packet, TokenPacket):
            print("Enviando token...")
        if isinstance(packet, DataPacket) and random.random() < self.error_probability:
            if add_error_chance == True:
                packet.crc = packet.crc[:-1] + ('0' if packet.crc[-1] == '1' else '1')
                self.logger.debug(f"Erro introduzido no pacote com destino: {packet.destination_name}")
                print("Erro introduzido no pacote com destino: {packet.destination_name}")
        time.sleep(3)
        self.socket.sendto(packet.header.encode(), (self.ip, self.port))
        if isinstance(packet, DataPacket):
            print("Pacote de dados enviado.")
            print('-'*50+'\n')
        elif isinstance(packet, TokenPacket):
            print("Token enviado.\n")
            print('-'*50+'\n')

        
    def receive_packet(self):
        data, _ = self.socket.recvfrom(1024)
        packet_type = Packet.get_packet_type(data.decode())
        packet = TokenPacket() if packet_type == "1000" else DataPacket.create_header_from_string(data.decode())
        print("Pacote recebido. Iniciando processamento...\n")
        time.sleep(3)
        return self.process_packet(packet)

            
    @classmethod
    def create_machine_from_file(cls, file_path: str, local_port: int = 6000):
        with open(file_path, 'r') as file:
            ip_and_port, nickname, time_token, has_token_str = [file.readline().strip() for _ in range(4)]
            has_token = has_token_str.lower() == "true"
        return cls(ip_and_port, nickname, time_token, has_token, local_port=local_port)

    
    def close_socket(self):
        self.socket.close()

        
    def run(self):
        if self.has_token == True:
            if len(self.message_queue) > 0:
                packet = self.message_queue[0]
                print(f"Segurando o token por {self.time_token} segundos...")
                time.sleep(int(self.time_token))  
                print(f"Enviando mensagem para: {packet.destination_name}")
                self.send_packet(packet, add_error_chance=True)
            else:
                print(f"Nenhuma mensagem para enviar, segurando o token por {self.time_token} segundos...\n")
                print('-'*50+'\n')
                time.sleep(int(self.time_token))  
                self.send_packet(self.token)
                self.has_token = False

        
    def process_packet(self, packet: Packet):

        if packet.id == "1000":
            self.last_token_time = time.time()
            print("Token recebido. Momento atual: ", self.last_token_time)
            if not self.has_token:
                self.has_token = True
                self.token = packet
                self.run()
            else:
                pass
            
        elif packet.id == "2000":
            if packet.destination_name == self.nickname:
                print("Pacote para mim!")
                calculated_crc = packet.calculate_crc() # calcula crc
                if calculated_crc == packet.crc:
                    packet.error_control = "ACK" # altera o estado
                    print(f"Mensagem recebida com sucesso! Conteúdo: {packet.message}")
                else:
                    packet.error_control = "NACK" # altera o estado
                    print(f"Erro na mensagem recebida. CRC divergente!")
                    
                time.sleep(2)
                
                print("Enviando pacote de volta...\n")
                print('-'*50+'\n')
                packet.header = packet.create_header() # cria o header
                self.send_packet(packet) # manda de volta 
                
            elif packet.origin_name == self.nickname:
                print("Pacote de volta!")
                print("Mensagem contida no pacote: ", packet.message + "\n")
                if packet.error_control == "ACK":
                    print(f"Mensagem enviada foi recebida pelo destino!")
                    self.message_queue.pop(0) # tira da fila
                    print("pacote removido da fila")
                    print("passando o token...")
                    self.send_packet(self.token) # manda o token
                    self.has_token = False # não tem mais o token
                    
                elif packet.error_control == "NACK":
                    print(f"Ocorreu um erro na mensagem")
                    self.send_packet(packet) # reenvia o pacote se houver erro
                    
                elif packet.error_control == "maquinanaoexiste":
                    print(f"Máquina não foi encontrada na rede.")
                    self.message_queue.pop(0) # tira da fila
                    print("enviando o token...")
                    self.send_packet(self.token) # manda o token
                    self.has_token = False # não tem mais o token
                
            elif packet.destination_name == "TODOS":
                print("Pacote para todos!")
                calculated_crc = packet.calculate_crc() # calcula crc
                if calculated_crc == packet.crc:
                    print(f"Mensagem recebida: {packet.message}")
                else:
                    self.logger.debug(f"Erro na mensagem: {packet.message}")
                    print(f"Erro na mensagem: {packet.message}")
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
            
            time_since_last_token = time.time() - self.last_token_time
            
            if time_since_last_token > self.TIMEOUT_VALUE:  # TIMEOUT_VALUE é o tempo máximo permitido sem ver o token
                print('\n'+'-'*50+'\n')
                print(f"Token não visto por muito tempo. Gerando novo token.")
                print('\n'+'-'*50+'\n')
                self.generate_token()
                self.last_token_time = time.time()
            
            elif time_since_last_token < self.MINIMUM_TIME:  # MINIMUM_TIME é o tempo mínimo esperado entre as passagens do token
                print('\n'+'-'*50+'\n')
                print(f"Token visto muito rapidamente. Retirando token da rede.")
                print('\n'+'-'*50+'\n')
                self.has_token = False


    def listen_for_packets(self):
        while not self.terminate_event.is_set():
            try:
                self.receive_packet()
            except Exception as e:
                print(f"Erro ao receber packet: {e}")

            
    def stop_listening(self):
        # Join the listening thread
        try:
            self.listen_thread.join(timeout=5)
        except Exception as e:
            print(f"Error joining listen_thread: {e}")

        # If there's a token checker thread, join it too
        if self.controls_token:
            try:
                self.token_checker_thread.join(timeout=5)
            except Exception as e:
                print(f"Error joining token_checker_thread: {e}")

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
                    print(packet.message)  # Ajuste conforme a estrutura do seu pacote

            else:
                print("Escolha inválida. Por favor, tente novamente.")
