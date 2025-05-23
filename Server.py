import socket
import threading
import os
import subprocess
import traceback
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def handle_system_command(command):
    """
    Execute system commands safely using subprocess
    """
    try:
        # Use subprocess.run with shell=False for security
        result = subprocess.run(command, capture_output=True, text=True, shell=False)
        if result.returncode == 0:
            return "SC", result.stdout
        else:
            return "EE", result.stderr
    except Exception as e:
        return "EE", ",404,"+str(e)

def aesDecryption(msg, key, nonce):
    """
    AES decryption function
    """    
    # Create a cipher object with the same key and nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(msg)    # Decrypt the ciphertext
    return plaintext.decode()

def handle_file_operations(command_parts):
    """
    Handle file and directory operations
    """
    try:
        cmd = command_parts[0]
        args = command_parts[1:]

        if cmd == "mkdir":
            os.makedirs(args[0], exist_ok=False)
            return "SC", f"Directory {args[0]} created successfully"
        elif cmd == "cp":
            # Copy file or directory
            if len(args) < 2:
                return "EE", "Insufficient arguments for copy"
            import shutil
            if os.path.isdir(args[0]):
                shutil.copytree(args[0], args[1])
            else:
                shutil.copy2(args[0], args[1])
            return "SC", f"Copied {args[0]} to {args[1]}"
        
        elif cmd == "chmod":
            # Change file permissions
            if len(args) < 2:
                return "EE", "Insufficient arguments for chmod"
            os.chmod(args[1], int(args[0], 8))
            return "SC", f"Changed permissions of {args[1]} to {args[0]}"
        
        elif cmd == "chown":
            # Change file ownership
            if len(args) < 2:
                return "EE", "Insufficient arguments for chown"
            import pwd, grp
            uid = pwd.getpwnam(args[0]).pw_uid
            gid = grp.getgrnam(args[1]).gr_gid
            os.chown(args[2], uid, gid)
            return "SC", f"Changed ownership of {args[2]} to {args[0]}:{args[1]}"
        
        elif cmd == "find":
            # Find files or directories
            import glob
            results = glob.glob(os.path.join(args[0], '**', args[1]), recursive=True)
            return "SC", "\n".join(results)
        
        elif cmd == "ln":
            # Create symbolic or hard link
            link_type = "-s" if len(args) > 2 and args[0] == "-s" else None
            if link_type:
                os.symlink(args[1], args[2])
                return "SC", f"Created symbolic link from {args[1]} to {args[2]}"
            else:
                os.link(args[0], args[1])
                return "SC", f"Created hard link from {args[0]} to {args[1]}"

        elif cmd == "ls":
            # List files and directories
            path = args[0] if args else '.'
            try:
                items = os.listdir(path)
                return "SC", "\n".join(items)
            except Exception as e:
                return "EE", f"Error listing directory: {str(e)}"
        
        elif cmd == "cd":
            os.chdir(args[0])
            return "SC", f"Changed directory to {os.getcwd()}"
        
        elif cmd in ["rmdir", "rd"]:
            os.rmdir(args[0])
            return "SC", f"Directory {args[0]} removed successfully"
        
        elif cmd == "del":
            os.remove(args[0])
            return "SC", f"File {args[0]} deleted successfully"
        
        elif cmd == "ren":
            os.rename(args[0], args[1])
            return "SC", f"Renamed {args[0]} to {args[1]}"
        
        elif cmd == "openRead":
            with open(args[0], 'r') as file:
                content = file.read()
            return "SC", content
        
        elif cmd == "openWrite":
            with open(args[0], 'w') as file:
                pass  # Just create the file
            return "SC", f"File {args[0]} opened in write mode"
        
        else:
            # For additional system commands
            return handle_system_command(command_parts)

    except FileNotFoundError:
        return "EE", f",401,File or directory not found: {args[0]}" # 401
    except PermissionError:
        return "EE", f",402,Permission denied for operation on {args[0]}" # 402
    except Exception as e:
        return "EE", ",404,"+str(e)

def send_encrypted_packet(client_socket, data, encryption_type, session_key):
    """
    Send encrypted data based on the chosen encryption method
    """
    if encryption_type == "A":  # AES
        cipher = AES.new(session_key, AES.MODE_GCM)
        encrypted_data, tag = cipher.encrypt_and_digest(data.encode())
        client_socket.send(f"DP,{encrypted_data.hex()},{cipher.nonce.hex()},{tag.hex()}".encode())
    elif encryption_type == "C":  # Caesar
        encrypted_data = caesarEncryption(data, session_key)
        client_socket.send(f"DP,{encrypted_data}".encode())
    else:
        client_socket.send(f"DP,{data}".encode())

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

def handle_client_operation_phase(client_socket, encryption_type=None, session_key=None):
    """
    Handle the operation phase of the RFMP protocol
    """
    try:
        while True:
            # Receive command packet
            command_packet = client_socket.recv(4096).decode()
            
            # Check for closing phase
            if command_packet == "End":
                print("*Client exited*")
                break
            
            # Parse command packet
            packet_parts = command_packet.split(",")
            
            if packet_parts[0] != "CM":
                client_socket.send("EE,Invalid Packet Type".encode())
                print("*Invalid packet type received*")
                continue
            
            # Extract command
            command_parts = packet_parts[1].split() # Split into array with whitespace as delimeter.

            # Handle data packet for write operations
            if command_parts[0] == "openWrite":
                # Recieve data packet
                data_packet = client_socket.recv(4096).decode()
                print("*Packet received*")
                if not data_packet.startswith("DP,"):
                    client_socket.send("EE,Expected Data Packet".encode())
                    print("*Invalid packet type received*")
                    continue
                print("Reached here")
                print(data_packet)
                # Extract and potentially decrypt data
                data = data_packet[3:]      # Removing the "DP," part from the data. (filtering)
                if encryption_type == "A":  # AES decryption
                    '''
                    For decryption:
                    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                    message = cipher.decrypt(ciphertext)
                    '''
                    encrypted_data_str, nonce_str = data.split(',',1)
                    encrypted_key_str = encrypted_data_str.strip("b'")
                    nonce_str = nonce_str.strip("b'")
                    if encrypted_data_str.endswith("'"): 
                        encrypted_data_str = encrypted_data_str[:-1]
                    if nonce_str.endswith("'"): 
                        nonce_str = nonce_str[:-1]
                    # Convert the string representation back to bytes
                    encrypted_data = bytes.fromhex(encrypted_key_str)
                    nonce = bytes.fromhex(nonce_str)
                    data = aesDecryption(encrypted_data,session_key, nonce)
                    #cipher = AES.new(session_key, AES.MODE_GCM, nonce=bytes.fromhex(nonce))
                    #data = cipher.decrypt_and_verify(bytes.fromhex(encrypted_data), bytes.fromhex(tag)).decode()
                elif encryption_type == "C":  # Caesar decryption
                    data = caesarEncryption(data, -session_key)
                
                # Write to file
                with open(command_parts[1], 'w') as file:
                    file.write(data)
                client_socket.send("SC,File written successfully".encode())
                continue
            # Handle other commands
            result_type, result_message = handle_file_operations(command_parts)
            
            # Send result back to client
            if result_type == "SC":
                if command_parts[0] == "openRead":
                    # For read operations, potentially encrypt the content
                    send_encrypted_packet(client_socket, result_message, encryption_type, session_key)
                else:
                    client_socket.send(f"SC,{result_message}".encode())
            else:
                client_socket.send(f"EE,{result_message}".encode())

    except Exception as e:
        print(f"Operation Phase Error: {e}")
        traceback.print_exc()
        client_socket.send(f"EE,404,{e}".encode())

def handleClient(client_socket, client_address):
    try:
        print(f"Connection from {client_address}")
        
        # Receive startup message
        startupMsg = client_socket.recv(1024).decode()
        specificationsArr = startupMsg.split(',')
        print("*Specifications received*")
        print(startupMsg)
    
        encryption_type = None  # declaration
        session_key = None      # declaration
        
        if specificationsArr[3] == '0':
            # Non-secured communication
            client_socket.send("CC".encode())
            print("*Confirm communication packet sent*")
            handle_client_operation_phase(client_socket)
        else:
            # Secured communication
            serverKeys = RSA.generate(2048)
            serverPrivateKey = serverKeys.export_key()
            serverPublicKey = serverKeys.publickey().export_key()
            
            # Send confirmation with public key
            commPacket = f"CC,{serverPublicKey.decode()}"
            client_socket.send(commPacket.encode())
            
            # Receive encryption packet
            encryptionPacket = client_socket.recv(4096).decode()
            encryptionPacketArr = encryptionPacket.split(",")
            encryption_type = encryptionPacketArr[1]
            print(encryptionPacketArr)
             # Remove any b' prefix and ' suffix from the encrypted session key
            encrypted_key_str = encryptionPacketArr[2].strip("b'")
            if encrypted_key_str.endswith("'"): 
                encrypted_key_str = encrypted_key_str[:-1]

            # Convert the string representation back to bytes
            encrypted_key = bytes.fromhex(encrypted_key_str)
            
            # Decrypt session key using server's private key
            cipher = PKCS1_OAEP.new(RSA.import_key(serverPrivateKey))
            session_key = cipher.decrypt(encrypted_key)

            
            # Proceed with secured operation phase
            handle_client_operation_phase(client_socket, encryption_type, session_key)
    
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
        traceback.print_exc() #REMOVE BEFORE SUBMITTING
    finally: 
        client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 8888

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((host, port))
        server.listen(10)
        print("Server is listening...")
        
        while True:
            try:
                client, addr = server.accept()
                clientThread = threading.Thread(target=handleClient, args=(client, addr)) # Accept multiple clients.
                clientThread.start()
            except Exception as e:
                print(f"Error accepting connection: {e}")
    except Exception as ex:
        print(f"Server error: {ex}")
    finally:
        server.close() # Make sure to close the server socket when done.

if __name__ == "__main__":
    main()
