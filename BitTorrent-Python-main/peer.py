import socket
import sys
import os
import hashlib
import json
import requests
import time
from tqdm import tqdm
from encode import bencode, bdecode
from threading import Thread
from requests.exceptions import ConnectionError, HTTPError

files = [] # This dictionary should contain piece index to data mapping
pieces_have = [] # This list should contain the indexes of the pieces that the client has

def connect_to_server(server_host, server_port, client_ip, client_port, client_id):
    try:
        payload = {'command': 'connect', 'port': client_port, 'ip': client_ip, 'id': client_id}
        response = requests.post(f'http://{server_host}:{server_port}/announce', json=payload)
        
        if response.ok:
            data = response.json()
            print("Status:", data.get('status'))
            print("Message:", data.get('message'))
        else:
            data = response.json()
            print("Failed to connect to server:", response.status_code)
            print("Message:", data.get('message'))
        return True
        
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def disconnect_from_server(server_host, server_port, client_ip, client_port, client_id):
    try:
        # Prepare the payload with disconnect command
        payload = {'command': 'disconnect', 'ip': client_ip, 'port': client_port, 'id': client_id}
        # Send the POST request to the server's endpoint
        response = requests.post(f'http://{server_host}:{server_port}/announce', json=payload)
        
        if response.ok:
            # Parse the JSON response from the server
            data = response.json()
            print("Status:", data.get('status'))
            print("Message:", data.get('message'))
        else:
            data = response.json()
            # Handle non-200 responses
            print("Failed to disconnect:", response.status_code)
            print("Message:", data.get('message'))
    except Exception as e:
        # Handle exceptions that may occur during the request
        print(f"An error occurred: {e}")

def create_torrent_file(server_host, server_port, filename, client_id):
    # Create torrent file
    dir = "peer_" + str(client_id)
    full_output_path = os.path.join(dir, filename)
    if not os.path.exists(full_output_path):
        print("You must have the file in the directory to create a torrent file!")
        return
    
    piece_length = 256*1024  # 256kB piece size
    file_size = os.path.getsize(full_output_path)
    num_pieces = (file_size + piece_length - 1) // piece_length  # Calculates the necessary number of pieces
    
    # Initialize the 'pieces' as bytes
    pieces = b''
    
    # Progress bar setup
    progress_bar = tqdm(total=num_pieces, unit='piece', desc='Creating torrent', leave=True)
    
    # Calculate SHA1 hash for each piece and concatenate
    with open(full_output_path, 'rb') as file:
        for _ in range(num_pieces):
            piece = file.read(piece_length)
            pieces += hashlib.sha1(piece).digest()  # Append the binary hash directly
            progress_bar.update(1)
    progress_bar.close()
    
    # Metadata for the torrent
    tracker_url = f'http://{server_host}:{server_port}/announce'
    metadata = {
        'announce': tracker_url,
        'info': {
            'name': filename,
            'length': file_size,
            'piece length': piece_length,
            'pieces': pieces,  # Assign the byte string containing all piece hashes
        }
    }
    # Ensure you bencode the entire metadata dictionary
    bencoded_data = bencode(metadata)
    
    torrent_filename = f"{filename}.torrent"
    full_output_path = os.path.join(dir, torrent_filename)
    with open(full_output_path, 'wb') as torrent_file:
        torrent_file.write(bencoded_data)

    print("Torrent file created")

def upload_info_hash_to_tracker(server_host, server_port, client_ip, client_port, client_id, filename):
    # Connect to the tracker and send torrent information
    try:
        dir = "peer_" + str(client_id)
        # Check if file and torrent file exist
        full_output_path = dir + "/" + filename
        if not os.path.exists(full_output_path):
            print("You don't have the file in the directory!")
            return
        
        torrent_filename = f"{filename}.torrent"
        full_output_path = dir + "/" + torrent_filename
        if not os.path.exists(full_output_path):
            print("Create torrent file before uploading!")
            return
        
        with open(full_output_path, 'rb') as file:
            metadata = bdecode(file.read())
            bencoded_info = bencode(metadata['info'])

        files.append({'filename': filename, 'pieces': metadata['info']['pieces']})
        headers = {'Content-Type': 'application/json'}
        data = {
            'command': 'upload info',
            'peer_ip': client_ip,
            'peer_port': client_port,
            'peer_id': client_id,
            'filename': filename,
            'info_hash': hashlib.sha1(bencoded_info).hexdigest()
        }
        
        try:
            response = requests.post(f'http://{server_host}:{server_port}/announce', json=data, headers=headers)
        
            if response.ok:
                print(f"Uploaded torrent info for {filename} to tracker")
                print("Received from server:", response.json())
            else:
                print("Failed to upload torrent info:", response.status_code)
                print(response.text)
        except (ConnectionError, HTTPError) as e:
            print(f"Failed to connect to tracker: {e}")
            return
    except Exception as e:
        print(f"An error occurred: {e}")

def download_torrent(torrent_filename, client_ip, client_id):
    # Decode the torrent file
    dir = "peer_" + str(client_id)
    full_output_path = dir + "/" + torrent_filename
    with open(full_output_path, 'rb') as file:
        torrent_data = bdecode(file.read())
        tracker_url = torrent_data['announce']
        info_hash = hashlib.sha1(bencode(torrent_data['info'])).hexdigest()
        filename = torrent_data['info']['name']
    
    all_hashes = torrent_data['info']['pieces']
    hash_length = 20  # SHA-1 hashes are 20 bytes long
    num_pieces = len(all_hashes) // hash_length
    piece_length = torrent_data['info']['piece length']
    
    validated_pieces = [None] * num_pieces
    peer_idx = 0
    i = 0
    while i < num_pieces:
        # Contact the tracker to get peers
        payload = {
            'command': 'get_peers',
            'info_hash': info_hash
        }
        try:
            response = requests.post(f'{tracker_url}', json=payload)
            if response.ok:
                data = response.json()
                if data['status'] == 'success':
                    print("Peers holding the file:", data['peers'])
                else:
                    print("No peers found or error:", data['message'])
                    break
            else:
                print("Failed to contact tracker:", response.status_code)
                print("Tracker recover, ask seeder connect again.")
                return
            
        except (ConnectionError, HTTPError) as e:
            print("Failed to contact tracker. Trying again in 5 seconds.")
            time.sleep(5)
            continue
        
        number_of_peers = len(data['peers'])
        while number_of_peers == 0:
            print("No peers found. Trying again in 5 seconds.")
            time.sleep(5)
            response = requests.post(f'{tracker_url}', json=payload)
            if response.ok:
                data = response.json()
                if data['status'] == 'success':
                    print("Peers holding the file:", data['peers'])
                    number_of_peers = len(data['peers'])
                else:
                    print("No peers found or error:", data['message'])
            else:
                print("Failed to contact tracker:", response.status_code)

        seeder_ip, seeder_port, seeder_id = data['peers'][peer_idx]['ip'], int(data['peers'][peer_idx]['port']), int(data['peers'][peer_idx]['id'])
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect((seeder_ip, seeder_port))
        except ConnectionRefusedError:
            print(f"Failed to connect to {seeder_ip}:{seeder_port}, trying next peer if available.")
            
            peer_idx += 1
            if(peer_idx == number_of_peers):
                peer_idx = 0
            time.sleep(5)
            continue
            
        peer_idx += 1
        if(peer_idx == number_of_peers):
            peer_idx = 0

        client_socket.send(f"get_piece {i} of {filename} at_peer {seeder_id} {client_ip}\n".encode())
        piece = client_socket.recv(piece_length)  # Use the full data receiver function mentioned before
        piece_hash = all_hashes[i * hash_length:(i + 1) * hash_length]
        if hashlib.sha1(piece).digest() == piece_hash:
            print(f"Received and validated piece {i} from {seeder_ip}:{seeder_port}")
            validated_pieces[i] = piece
            i = i + 1
        else:
            print(f"Piece {i} is corrupted")
            continue
        
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()
        time.sleep(5)
    
    #Create directory if not exists
    directory = "peer_" + str(client_id)
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    full_output_path = os.path.join(directory, torrent_data['info']['name'])
    with open(full_output_path, 'wb') as file:
        for piece in validated_pieces:
            if piece is not None:
                file.write(piece)
    print(f"File has been successfully created")
    print("Download completed and connection closed.")

def send_file_piece(client_socket, file_name, peer_id, piece_index, piece_size, file_pieces):
    # Calculate the byte offset for the requested piece
    offset = piece_index * piece_size
    if piece_index < len(file_pieces):
        dir = "peer_" + str(peer_id)
        full_output_path = os.path.join(dir, file_name)
        with open(full_output_path, 'rb') as file:
            file.seek(offset)
            piece_data = file.read(piece_size)
            if piece_data:
                client_socket.sendall(piece_data)
                print(f"Sent piece index {piece_index}")
            else:
                print("No data read from file; possible end of file.")
    else:
        print(f"Piece index {piece_index} is out of range.")

def start_seeder_server(ip, port):
    def client_handler(client_socket):
        try:
            while True:
                request = client_socket.recv(1024)
                if request.startswith(b'get_piece'):
                    decoded_request = request.decode('utf-8')
                    piece_index = int(decoded_request.split()[1])
                    file_name = decoded_request.split()[3]
                    seeder_id = int(decoded_request.split()[5])
                    client_ip = decoded_request.split()[6]
                    print("Connection from", client_ip, "for piece", piece_index, "of", file_name)
                    for file in files:
                        if file['filename'] == file_name:
                            file_pieces = file['pieces']
                            piece_size = 256 * 1024
                            send_file_piece(client_socket, file_name, seeder_id, piece_index, piece_size, file_pieces)
                            break
                    
                    return
                else:
                    print("No valid request received.")
                    return
                    
        except socket.error as e:
            print("Socket error:", e)
            client_socket.close()
        finally:
            client_socket.close()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    print("Seeder listening on", ip, ":", port)

    while True:
        client_socket, addr = server_socket.accept()
        Thread(target=client_handler, args=(client_socket,), daemon=True).start()

def start_leecher_server(torrent_filename, ip, id):
    while True:
        Thread(target=download_torrent, args=(torrent_filename, ip, id), daemon=True).start()

def main(SERVER_HOST, SERVER_PORT, CLIENT_IP, CLIENT_PORT, CLIENT_ID):
    status = connect_to_server(SERVER_HOST, SERVER_PORT, CLIENT_IP, CLIENT_PORT, CLIENT_ID)
    if status == False:
        return
    
    while True:
        command = input("Enter a command (create torrent, upload, download, disconnect, seeder, exit): ")
        if(command == "connect"):
            connect_to_server(SERVER_HOST, SERVER_PORT, CLIENT_IP, CLIENT_PORT, CLIENT_ID)
        if(command == "disconnect"):
            disconnect_from_server(SERVER_HOST, SERVER_PORT, CLIENT_IP, CLIENT_PORT, CLIENT_ID)
            break
        elif(command == "upload"):
            FILENAME = input("Enter the filename to seed: ")
            upload_info_hash_to_tracker(SERVER_HOST, SERVER_PORT, CLIENT_IP, CLIENT_PORT, CLIENT_ID, FILENAME)
        elif command == "download":
            TORRENT_FILE = input("Enter torrent file name: ")
            Thread(target=download_torrent, args=(TORRENT_FILE, CLIENT_IP, CLIENT_ID), daemon=True).start()
        elif command == "create torrent":
            FILENAME = input("Enter the filename to create torrent file: ")
            create_torrent_file(SERVER_HOST, SERVER_PORT, FILENAME, CLIENT_ID)
        elif command == "seeder":
            # Start seeder server in a separate thread
            Thread(target=start_seeder_server, args=(CLIENT_IP, CLIENT_PORT), daemon=True).start()
        elif(command == "exit"):
            break

if __name__ == "__main__":
    if sys.argv.__len__() != 6:
        print("Usage: python peer.py {server ip} {server port} {client ip} {client port} {client id}")
        sys.exit(1)

    SERVER_HOST = sys.argv[1]  # The server's hostname or IP address
    SERVER_PORT = int(sys.argv[2])  # The port used by the server as an integer
    CLIENT_IP = sys.argv[3]  # The advertised IP address of the client
    CLIENT_PORT = int(sys.argv[4])  # The advertised port number of the client as an integer
    CLIENT_ID = sys.argv[5]  # The unique ID of the client
    main(SERVER_HOST, SERVER_PORT, CLIENT_IP, CLIENT_PORT, CLIENT_ID)