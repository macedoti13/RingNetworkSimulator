import zlib
from .packet import Packet

class DataPacket(Packet):
    """
    Pacote de dados. O pacote de dados é um pacote que carrega uma mensagem entre os nós da rede.

    Args:
        Packet (class): Classe base para todos os pacotes da rede.
    """    
    
    def __init__(self, origin_name: str, destination_name: str, error_control: str, message: str = "") -> None:
        super().__init__("2000")
        self.origin_name = origin_name
        self.destination_name = destination_name 
        self.error_control = error_control
        self.message = message
        self.crc = self.calculate_crc()
        self.header = self.create_header()
        
        
    def create_header(self):
        """
        Cria o cabeçalho do pacote de dados. O cabeçalho é a string que é enviada entre os nós da rede. 

        Returns:
            str: Cabecalho do pacote de dados.
        """        
        return f"{self.id};{self.origin_name}:{self.destination_name}:{self.error_control}:{self.crc}:{self.message}"
    
    
    def calculate_crc(self) -> int:
        """
        Calcula o CRC da mensagem do pacote de dados. O CRC é um código de verificação de erros que é usado
        para verificar se a mensagem foi corrompida durante a transmissão.

        Returns:
            int: CRC da mensagem do pacote de dados.
        """        
        return zlib.crc32(self.message.encode())
    
    
    @classmethod
    def create_header_from_string(cls, header: str):
        """
        Cria um objeto DataPacket a partir de uma string de cabeçalho.

        Args:
            header (str): Cabeçalho do pacote de dados.

        Returns:
            DataPacket: Objeto DataPacket criado a partir do cabeçalho.
        """        
        header = header.split(";")
        content = header[1].split(':')
        return DataPacket(content[0], content[1], content[2], content[4])
