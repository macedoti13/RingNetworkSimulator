from abc import ABC, abstractmethod

class Packet(ABC):
    """
    Classe base para todos os pacotes da rede. Um pacote é uma mensagem que é enviada entre os nós da rede.

    Args:
        ABC (class): Classe abstrata do Python.
    """    
    
    def __init__(self, id: str) -> None:
        self.id = id
        
        
    @abstractmethod
    def create_header(self):
        """
        Método abstrato que cria o cabeçalho do pacote. Implementado nas classes filhas.
        """        
        pass
    
    
    @classmethod
    def get_packet_type(cls, header: str):
        """
        Pega o tipo do pacote a partir do cabeçalho do pacote. 
        O tipo do pacote pode ser "1000" (token) ou "2000" (dados).

        Args:
            header (str): Header do pacote.

        Returns:
            str: Tipo do pacote.
        """        
        return header.split(";")[0]