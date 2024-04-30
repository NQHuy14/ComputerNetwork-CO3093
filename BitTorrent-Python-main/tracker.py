import threading
import json
import sys
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configuration
MAX_PEERS = 10       # Maximum number of peers

# Global list to store peer information
peers = []
torrents = {}
file_metadata = {}

# Lock to handle thread synchronization for the peers list
lock = threading.Lock()

@app.route('/announce', methods=['POST'])
def announce():
    print("The server is listening...")

    data = request.json
    if 'command' in data:
        if data['command'] == 'connect':
            return handle_connect(data)
        elif data['command'] == 'disconnect':
            return handle_disconnect(data)
        elif data['command'] == 'upload info':
            return handle_upload(data)
        elif data['command'] == 'get_peers':
            return handle_get_peers(data)
    return jsonify({'status': 'error', 'message': 'Invalid command'}), 400

def handle_connect(data):
    with lock:
        if len(peers) < MAX_PEERS:
            client_ip = data['ip']
            client_port = data['port']
            client_id = data['id']
            for peer in peers:
                if peer['ip'] == client_ip and peer['port'] == client_port:
                    print("This peer already connected")
                    return jsonify({'status': 'fail', 'message': 'You have already connected'}), 400
            peers.append({'ip': client_ip, 'port': client_port, 'id': client_id})
            print(f"Peer {client_ip}, {client_port} has connected to server")
            print("Current list of connected peers:")
            for peer in peers:
                print(f"Peer IP: {peer['ip']}, Port: {peer['port']}, ID: {peer['id']}")  
            return jsonify({'status': 'success', 'message': 'Connection established'}), 200

def handle_disconnect(data):
    with lock:
        client_ip = data['ip']
        client_port = data['port']
        for peer in peers:
            if peer['ip'] == client_ip and peer['port'] == client_port:
                peers.remove(peer)
                print(f"Peer {client_ip}, {client_port} has disconnected from server")
                print("Current list of connected peers:")
                for peer in peers:
                    print(f"Peer IP: {peer['ip']}, Port: {peer['port']}")
                return jsonify({'status': 'success', 'message': 'Connection terminated'}), 200
        return jsonify({'status': 'error', 'message': 'Peer not found'}), 404

def handle_get_peers(data):
    with lock:
        info_hash = data['info_hash']
        if info_hash in torrents:
            peer_info = [peer for peer in torrents[info_hash]['peers']]
            return jsonify({'status': 'success', 'message': 'Peer data retrieved', 'peers': peer_info}), 200
        return jsonify({'status': 'error', 'message': 'Torrent not found'}), 404

def handle_upload(data):
    with lock:  
        filename = data['filename']
        info_hash = data['info_hash']
        peer_ip = data['peer_ip']
        peer_port = data['peer_port']
        peer_id = data['peer_id']

        # Check if the torrent already exists in the tracker data
        if info_hash not in torrents:
            torrents[info_hash] = {
                'filename': filename,
                'peers': []
            }
        
        # Add or update peer information for this torrent
        peer_info = {'ip': peer_ip, 'port': peer_port, 'id': peer_id}
        if peer_info not in torrents[info_hash]['peers']:
            torrents[info_hash]['peers'].append(peer_info)

        return jsonify({'status': 'success', 'message': 'Torrent info registered successfully'}), 200

if __name__ == "__main__":
    if sys.argv.__len__() != 3:
        print("Usage: python tracker.py {server ip} {server port}")
        sys.exit(1)
    HOST = sys.argv[1]  # The server's hostname or IP address
    PORT = int(sys.argv[2])  # The port used by the server as an integer
    print("The server is listening...")
    app.run(host=HOST, port=PORT)