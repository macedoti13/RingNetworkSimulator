from typing import Optional
from .message_queue import MessageQueue

class NetworkNode:
    
    def __init__(self,
                 IP: str,
                 nickname: str,
                 right_neighbor: Optional[str],
                 has_token: bool = False) -> None:
        
        self.IP = IP
        self.nickname = nickname
        self.right_neighbor = right_neighbor
        self.has_token = has_token
        self.message_queue = MessageQueue()
        
        
    def send_message(target: str, content: str):
        pass