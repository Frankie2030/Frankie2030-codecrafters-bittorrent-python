import bencodepy
import hashlib
import requests
import sys
import struct
import urllib.parse
import socket
import random


def calculate_info_hash(torrent_file_path):
    with open(torrent_file_path, 'rb') as file:
        bencoded_content = file.read()

    decoded_content = bencodepy.decode(bencoded_content)
    info_dict = decoded_content[b'info']
    bencoded_info = bencodepy.encode(info_dict)
    info_hash = hashlib.sha1(bencoded_info).digest()
    return info_hash


def get_tracker_url(torrent_file_path):
    with open(torrent_file_path, 'rb') as file:
        bencoded_content = file.read()

    decoded_content = bencodepy.decode(bencoded_content)
    return decoded_content[b'announce'].decode('utf-8')


def make_tracker_request(torrent_file_path):
    # Calculate info hash
    info_hash = calculate_info_hash(torrent_file_path)
    # Get tracker URL
    tracker_url = get_tracker_url(torrent_file_path)

    # Set query parameters
    params = {
        'info_hash': urllib.parse.quote(info_hash),
        'peer_id': '-PC0001-' + '123456789012',  # Example peer_id (20 bytes long)
        'port': 6881,
        'uploaded': 0,
        'downloaded': 0,
        'left': 0,  # Should be the total file size. Assume 0 for simplicity.
        'compact': 1
    }

    # Make GET request to tracker
    response = requests.get(tracker_url, params=params)

    if response.status_code == 200:
        decoded_response = bencodepy.decode(response.content)
        return decoded_response[b'peers']
    else:
        print(f"Failed to connect to tracker. Status code: {response.status_code}")
        sys.exit(1)


def parse_peers(peers):
    peer_list = []
    for i in range(0, len(peers), 6):
        ip = struct.unpack('!BBBB', peers[i:i + 4])
        ip_str = '.'.join(map(str, ip))
        port = struct.unpack('!H', peers[i + 4:i + 6])[0]
        peer_list.append((ip_str, port))
    return peer_list


def perform_handshake(torrent_file_path, peer_ip, peer_port):
    info_hash = calculate_info_hash(torrent_file_path)
    peer_id = bytes(random.getrandbits(8) for _ in range(20))

    # Create handshake message
    pstr = b"BitTorrent protocol"
    pstrlen = len(pstr)
    reserved = bytes(8)
    handshake_msg = struct.pack(f"!B{pstrlen}s8s20s20s", pstrlen, pstr, reserved, info_hash, peer_id)

    # Connect to the peer and send handshake
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, peer_port))
        s.sendall(handshake_msg)

        # Receive handshake response
        response = s.recv(68)
        if len(response) != 68:
            print("Invalid handshake response length.")
            sys.exit(1)

        # Unpack the response and extract the peer ID
        _, _, _, _, received_peer_id = struct.unpack(f"!B{pstrlen}s8s20s20s", response)
        print(f"Peer ID: {received_peer_id.hex()}")


def main():
    if len(sys.argv) < 3:
        print("Usage: ./your_bittorrent.sh <command> <torrent_file> [<peer_ip>:<peer_port>]")
        sys.exit(1)

    command = sys.argv[1]
    torrent_file_path = sys.argv[2]

    if command == 'peers':
        peers_bencoded = make_tracker_request(torrent_file_path)
        peer_list = parse_peers(peers_bencoded)

        for peer in peer_list:
            print(f"{peer[0]}:{peer[1]}")
    elif command == 'handshake':
        if len(sys.argv) != 4:
            print("Usage: ./your_bittorrent.sh handshake <torrent_file> <peer_ip>:<peer_port>")
            sys.exit(1)

        peer_ip, peer_port = sys.argv[3].split(":")
        peer_port = int(peer_port)
        perform_handshake(torrent_file_path, peer_ip, peer_port)
    else:
        print("Unknown command.")
        sys.exit(1)


if __name__ == '__main__':
    main()
