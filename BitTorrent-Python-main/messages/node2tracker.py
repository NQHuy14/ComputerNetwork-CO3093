from messages.message import Message

class Node2Tracker(Message):
    def __init__(self, node_id: int, mode: int, filename: str):

        super().__init__()
        self.node_id = node_id
        self.filename = filename
        self.mode = mode
    def to_json(self):
        return {
            "node_id": self.node_id,
            "mode": self.mode,
            "filename": self.filename
        }