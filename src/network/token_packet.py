from .packet import Packet

class TokenPacket(Packet):
    """
    Classe que representa um pacote de token. O pacote de token é um pacote especial que é enviado
    entre os nós da rede para controlar o acesso ao canal de comunicação. O pacote de token é
    representado pelo cabeçalho "1000".

    Args:
        Packet (Packet): A classe base para todos os pacotes da rede.
    """    
    
    def __init__(self) -> None:
        super().__init__("1000")
        self.header = self.create_header()
        
        
    def create_header(self):
        """
        Cria o cabeçalho do pacote de token.

        Returns:
            str: Cabeçalho do pacote de token. A string "1000".
        """        
        return f"{self.id}"