import socket
import random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

PORT = 8888

def caesarEncryption(msg, key):
    """
    Caesar cipher encryption function
    """
    encrypted_msg = ""
    for char in msg:
        if char.islower():
            encrypted_msg += chr((ord(char) + key - ord('a')) % 26 + ord('a'))
        elif char.isupper():
            encrypted_msg += chr((ord(char) + key - ord('A')) % 26 + ord('A'))
        else:
            encrypted_msg += char
    return encrypted_msg

def aesEncryption(msg, key):
    """
    AES encryption function
    """
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(msg.encode())
    return ciphertext,cipher.nonce #NEW ADDITION HERE -----------------------------------------------

def client_operation_phase(s, encryption_type=None, session_key=None):
    """
    Handle the operation phase of the RFMP protocol
    """
    while True:
        # Display menu of operations
        print("\n--- Remote File Management Protocol ---")
        print("Available Commands:")
        print("1. mkdir - Create directory")
        print("2. cd - Change directory")
        print("3. rmdir/rd - Remove directory")
        print("4. del - Delete file")
        print("5. ren - Rename file/directory")
        print("6. openRead - Read file contents")
        print("7. openWrite - Write to file")
        print("8. cp - Copy file/directory")
        print("9. chmod - Change file permissions")
        print("10. chown - Change file ownership")
        print("11. find - Search for files")
        print("12. ls - show all files/ folders")
        print("13. Exit")
        
        choice = input("Enter your choice (1-13): ")
        
        try:
            if choice == "13":
                # Close connection
                s.send("End".encode())
                break
            
            # Prepare command packet
            if choice == "1":
                dirname = input("Enter directory name: ")
                command = f"CM,mkdir {dirname}"
                print(command)
            elif choice == "2":
                path = input("Enter new directory path: ")
                command = f"CM,cd {path}"
                print(command)
            elif choice == "3":
                dirname = input("Enter directory to remove: ")
                command = f"CM,rmdir {dirname}"
                print(command)
            elif choice == "4":
                filename = input("Enter file to delete: ")
                command = f"CM,del {filename}"
                print(command)
            elif choice == "5":
                old_name = input("Enter current name: ")
                new_name = input("Enter new name: ")
                command = f"CM,ren {old_name} {new_name}"
                print(command)
            elif choice == "6":
                filename = input("Enter file to read: ")
                command = f"CM,openRead {filename}"
                print(command)
            elif choice == "7":
                filename = input("Enter file to write: ")
                command = f"CM,openWrite {filename}"
                print(command)
            elif choice == "8":
                src = input("Enter source file/directory: ")
                dest = input("Enter destination: ")
                command = f"CM,cp {src} {dest}"
                print(command)
            elif choice == "9":
                mode = input("Enter permission mode (e.g., 755): ")
                filename = input("Enter file/directory: ")
                command = f"CM,chmod {mode} {filename}"
                print(command)
            elif choice == "10":
                user = input("Enter new owner: ")
                group = input("Enter new group: ")
                filename = input("Enter file/directory: ")
                command = f"CM,chown {user} {group} {filename}"
                print(command)
            elif choice == "11":
                path = input("Enter search path: ")
                pattern = input("Enter search pattern: ")
                command = f"CM,find {path} {pattern}"
                print(command)
            elif choice == "12":
                path = input("Enter directory path (. for current): ")
                command = f"CM,ls {path}"
                print(command)
            else:
                print("Invalid choice. Try again.")
                continue
            
            # Send command packet
            s.send(command.encode())
            print("*Command packet sent*")
            print("("+command+")")
            
            # Handle specific file write operation
            if choice == "7":
                content = input("Enter file contents: ")
                
                # Encrypt content if encryption is enabled
                if encryption_type == "A":  # AES
                    encrypted_content,nonce = aesEncryption(content, session_key)
                    s.send(f"DP,{encrypted_content.hex()},{nonce.hex()}".encode())
                    print("*AES encrypted Data Packet sent*")
                elif encryption_type == "C":  # Caesar
                    encrypted_content = caesarEncryption(content, session_key)
                    s.send(f"DP,{encrypted_content}".encode())
                    print("*Caesar encrypted Data Packet sent*")
                else:
                    s.send(f"DP,{content}".encode())
                    print("*Data Packet sent*")
            # Receive and process server response
            response = s.recv(4096).decode()
            # Handle read operation response with potential decryption
            if (choice == "6" or choice in ["11"]) and response.startswith("DP,"):
                content = response[3:]
                if encryption_type == "A":  # AES -------------------------------------------------------------
                    cipher = AES.new(session_key, AES.MODE_CTR)
                    content = cipher.decrypt(bytes.fromhex(content)).decode()
                elif encryption_type == "C":  # Caesar
                    content = caesarEncryption(content, -session_key)
                print("File Contents:\n", content)
            else:
                print("Server Response:", response)
        except Exception as e:
            print(f"Error during operation: {e}")

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    s.connect((host, PORT))
    
    try:
        # Security setup
        print("Would you like your communication to be secured?")
        securityIN = input("Y/N: ").strip().upper()
        
        if securityIN == 'Y':
            SECURITY = 1
        elif securityIN == 'N':
            SECURITY = 0
        else:
            print("Invalid input.")
            exit()
        print(f"(SS,RFMP,v1.0,{SECURITY})")
        # Send start packet
        specifications = f"SS,RFMP,v1.0,{SECURITY}"
        s.send(specifications.encode())
        
        # Receive confirmation
        confConnection = s.recv(4096).decode()
        print("Communication packet: ("+confConnection+")")
        
        # Determine communication type
        if confConnection == "CC":
            client_operation_phase(s)
        else:
            # Secured communication
            cc, serverPublicKey = confConnection.split(",", 1)
            
            # Generate client keys and session key
            clientKeys = RSA.generate(2048)
            clientPublicKey = clientKeys.publickey().export_key()
            
            cipher = PKCS1_OAEP.new(RSA.import_key(serverPublicKey.encode())) # Encode ServerPubKey because it was decoded when transferring with the CC packet.
            
            # Choose encryption method
            while True:
                encryptionAlgorithm = input("Encryption using AES or Caesar (A/C)? ").strip().upper()
                if encryptionAlgorithm in ["A", "C"]:
                    break
                print("Invalid input.")
            
            # Prepare session key   
            if encryptionAlgorithm == "A":
                sessionKey = get_random_bytes(16)
                encryptedSessionKey = cipher.encrypt(sessionKey)
            else:  # Caesar
                sessionKey = random.randint(1, 26)
                encryptedSessionKey = cipher.encrypt((str(sessionKey)).encode())
            # Prepare and send encryption packet
            #encryptionPacket = f"EC,{encryptionAlgorithm},{encryptedSessionKey.decode()},{clientPublicKey.decode()}"
            #encryptionPacket = ("EC".encode() + 
            #        f",{encryptionAlgorithm.encode()},{encryptedSessionKey},{clientPublicKey}".encode())
            #encryptionPacket = ("EC".encode() + 
            #        f",{encryptionAlgorithm},{encryptedSessionKey},{clientPublicKey}".encode())
            encryptedSessionKeySTR = encryptedSessionKey.hex()
            clientPublicKeySTR = clientPublicKey.hex()
            print(encryptedSessionKeySTR)
            encryptionPacket = f"EC,{encryptionAlgorithm},{encryptedSessionKeySTR},{clientPublicKeySTR}"
            s.send(encryptionPacket.encode())
            print("*Encryption packet sent*")
            print(encryptionPacket)
            
            # Proceed with secured operation phase
            client_operation_phase(s, encryptionAlgorithm, sessionKey)
    
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    main()