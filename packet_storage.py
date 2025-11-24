# packet_storage.py
import pickle

class PacketStorage:
    @staticmethod
    def save_packets(packets, filename):
        """Save packets to a file using pickle."""
        with open(filename, 'wb') as f:
            pickle.dump(packets, f)

    @staticmethod
    def load_packets(filename):
        """Load packets from a file using pickle."""
        with open(filename, 'rb') as f:
            return pickle.load(f)
