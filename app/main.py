import json
import sys
import bencodepy
import hashlib
import struct
import math
import socket
import requests
import os


def decode_bencode(bencoded_value):
    return bencodepy.decode(bencoded_value)


def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    elif isinstance(data, dict):
        return {bytes_to_str(key): bytes_to_str(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [bytes_to_str(item) for item in data]
    else:
        return data


def read_torrent_file(file_path):
    with open(file_path, "rb") as file:
        return file.read()


def get_info_hash(info_dict):
    bencoded_info = bencodepy.encode(info_dict)
    return hashlib.sha1(bencoded_info).hexdigest()


def print_torrent_info(decoded_data):
    tracker_url = decoded_data[b"announce"].decode()
    length = decoded_data[b"info"][b"length"]
    info_hash = get_info_hash(decoded_data[b"info"])
    piece_length = decoded_data[b"info"][b"piece length"]
    pieces = decoded_data[b"info"][b"pieces"]

    print(f"Tracker URL: {tracker_url}")
    print(f"Length: {length}")
    print(f"Info Hash: {info_hash}")
    print(f"Piece Length: {piece_length}")
    print(f"Piece Hashes: {extract_pieces_hashes(pieces)}")

def extract_pieces_hashes(pieces_hashes):
    index, result = 0, []
    while index < len(pieces_hashes):
        result.append(pieces_hashes[index : index + 20].hex())
        index += 20
    return result


def handle_decode_command(bencoded_value):
    print(json.dumps(bytes_to_str(decode_bencode(bencoded_value.encode()))))


def handle_info_command(torrent_file_path):
    bencoded_data = read_torrent_file(torrent_file_path)
    decoded_data = decode_bencode(bencoded_data)
    print_torrent_info(decoded_data)

def get_peers(decoded_data):
    tracker_url = decoded_data[b"announce"].decode()
    info_hash = hashlib.sha1(bencodepy.encode(decoded_data[b"info"])).digest()
    params = {
        "info_hash": info_hash,
        "peer_id": "IloveQBitTorrent2030",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": decoded_data[b"info"][b"length"],
        "compact": 1,
    }
    response = requests.get(tracker_url, params=params)
    response_dict = decode_bencode(response.content)
    peers = response_dict[b"peers"]
    peer_list = []
    for i in range(0, len(peers), 6):
        ip = ".".join(str(b) for b in peers[i : i + 4])
        port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
        peer_list.append((ip, port))
    return peer_list

def handle_peers_command(torrent_file_path):
    bencoded_data = read_torrent_file(torrent_file_path)
    decoded_data = decode_bencode(bencoded_data)
    peer_list = get_peers(decoded_data)
    for peer in peer_list:
        print(f"Peer: {peer[0]}:{peer[1]}")

def perform_handshake(decoded_data, ip, port):
    info_hash = hashlib.sha1(bencodepy.encode(decoded_data[b"info"])).digest()
    handshake = (
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + b"IloveQBitTorrent2030"
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    s.send(handshake)
    return s

def handle_handshake_command(file_name, peer_address):
    ip, port = peer_address.split(":")
    bencoded_data = read_torrent_file(file_name)
    parsed = decode_bencode(bencoded_data)
    s = perform_handshake(parsed, ip, port)
    peer_id = s.recv(68)[48:].hex()
    print(f"Peer ID: {peer_id}")

def receive_message(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    # If we didn't receive the full message for some reason, keep gobbling.
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message

def handle_download_piece_command(output_file, torrent_file_path, piece_index):
    piece_index = int(piece_index)
    bencoded_data = read_torrent_file(torrent_file_path)
    decoded_data = decode_bencode(bencoded_data)

    # Get peers from tracker
    peers = get_peers(decoded_data)
    ip, port = peers[0]
    
    # Perform handshake with decoded data
    s = perform_handshake(decoded_data, ip, port)

    try:
        response = s.recv(68)
        message = receive_message(s)
        while int(message[4]) != 5:
            message = receive_message(s)
        interested_payload = struct.pack(">IB", 1, 2)
        s.sendall(interested_payload)
        message = receive_message(s)
        while int(message[4]) != 1:
            message = receive_message(s)
        file_length = decoded_data[b"info"][b"length"]
        total_number_of_pieces = len(extract_pieces_hashes(decoded_data[b"info"][b"pieces"]))
        default_piece_length = decoded_data[b"info"][b"piece length"]
        if piece_index == total_number_of_pieces - 1:
            piece_length = file_length - (default_piece_length * piece_index)
        else:
            piece_length = default_piece_length
        number_of_blocks = math.ceil(piece_length / (16 * 1024))
        data = bytearray()
        for block_index in range(number_of_blocks):
            begin = 2**14 * block_index
            #print(f"begin: {begin}")
            block_length = min(piece_length - begin, 2**14)
            #print(f"Requesting block {block_index + 1} of {number_of_blocks} with length {block_length}")
            request_payload = struct.pack(">IBIII", 13, 6, piece_index, begin, block_length)
            # print("Requesting block, with payload:")
            # print(request_payload)
            # print(struct.unpack(">IBIII", request_payload))
            # print(int.from_bytes(request_payload[:4]))
            # print(int.from_bytes(request_payload[4:5]))
            # print(int.from_bytes(request_payload[5:9]))
            # print(int.from_bytes(request_payload[17:21]))
            s.sendall(request_payload)
            message = receive_message(s)
            data.extend(message[13:])
        with open(output_file, "wb") as f:
            f.write(data)
    finally:
        s.close()
    return data

def handle_download_command(output_file, torrent_file_path):
    bencoded_data = read_torrent_file(torrent_file_path)
    decoded_data = decode_bencode(bencoded_data)
    num_pieces = len(extract_pieces_hashes(decoded_data[b"info"][b"pieces"]))
    
    torrent_data = bytearray()

    # Step 5: Loop through each piece and download it
    for piece_index in range(num_pieces):
        #print(f"Downloading piece {piece_index + 1} of {num_pieces}")
        # Use handle_download_piece_command to download each piece
        piece_data = handle_download_piece_command(output_file, torrent_file_path, piece_index)
        
        # Extend the torrent data with the piece data
        torrent_data.extend(piece_data)

    # Step 6: Write the assembled data to the output file
    with open(output_file, "wb") as f:
        f.write(torrent_data)
    print(f"Download complete. File saved as {output_file}")

def main():
    command = sys.argv[1]
    if command == "decode":
        handle_decode_command(sys.argv[2])
    elif command == "info":
        handle_info_command(sys.argv[2])
    elif command == "peers":
        handle_peers_command(sys.argv[2])
    elif command == "handshake":
        handle_handshake_command(sys.argv[2], sys.argv[3])
    elif command == "download_piece":
        handle_download_piece_command(sys.argv[3], sys.argv[4], sys.argv[5])
    elif command == "download":
        handle_download_command(sys.argv[3], sys.argv[4])
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()