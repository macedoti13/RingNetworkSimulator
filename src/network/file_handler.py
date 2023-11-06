import logging

class FlushingFileHandler(logging.FileHandler):
    """
    Classe customizada para o logger do Python. Essa classe é responsável por criar um logger que
    escreve no arquivo de log a cada mensagem que é enviada para o logger.

    Args:
        logging (class): Classe de logging do Python.
    """    
    
    def emit(self, record):
        """
        Escreve a mensagem no arquivo de log e faz o flush do buffer do arquivo.

        Args:
            record (class): Classe de registro do Python.
        """        
        super().emit(record)
        self.flush()
    