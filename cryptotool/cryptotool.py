# cryptotool.py

import hashlib
from cryptography.fernet import Fernet

# Encryption & Decryption with Fernet
class CryptoTool:
    def __init__(self):
        # Generates and stores a key for symmetric encryption
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt_message(self, message: str) -> str:
        """
        Encrypts a message using Fernet symmetric encryption.
        
        :param message: Message to encrypt (string)
        :return: Encrypted message (string)
        """
        encrypted_message = self.cipher.encrypt(message.encode())
        return encrypted_message.decode()

    def decrypt_message(self, encrypted_message: str) -> str:
        """
        Decrypts a message using Fernet symmetric encryption.
        
        :param encrypted_message: Encrypted message (string)
        :return: Decrypted message (string)
        """
        decrypted_message = self.cipher.decrypt(encrypted_message.encode())
        return decrypted_message.decode()

    def hash_message(self, message: str) -> str:
        """
        Generates an SHA-256 hash of the input message.
        
        :param message: Message to hash (string)
        :return: Hashed message (string)
        """
        hashed_message = hashlib.sha256(message.encode()).hexdigest()
        return hashed_message


if __name__ == "__main__":
    tool = CryptoTool()

    # Sample usage
    message = "Hello, Lord Stef!"
    print(f"Original Message: {message}")

    # Encrypting the message
    encrypted = tool.encrypt_message(message)
    print(f"Encrypted Message: {encrypted}")

    # Decrypting the message
    decrypted = tool.decrypt_message(encrypted)
    print(f"Decrypted Message: {decrypted}")

    # Hashing the message
    hashed = tool.hash_message(message)
    print(f"Hashed Message: {hashed}")
