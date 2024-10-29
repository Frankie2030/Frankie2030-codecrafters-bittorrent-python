import json
import sys
import bencodepy
import hashlib
import struct
import socket
import requests
import math

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
    
def extract_info_hash(bencoded_value):
    _, bencoded_value_from_info = bencoded_value.split(b"info")
    dict_length = decode_bencode(bencoded_value_from_info)
    return bencoded_value_from_info[:dict_length]
def extract_pieces_hashes(pieces_hashes):
    index, result = 0, []
    while index < len(pieces_hashes):
        result.append(pieces_hashes[index : index + 20].hex())
        index += 20
    return result
def get_peers(decoded_data, info_hash):
    params = {
        "info_hash": info_hash,
        "peer_id": "PC0001-7694471987235",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": decoded_data["info"]["length"],
        "compact": 1,
    }
    response = requests.get(decoded_data["announce"].decode(), params=params)
    return decode_peers(decode_bencode(response.content)[0]["peers"])
def decode_peers(peers):
    index, result = 0, []
    while index < len(peers):
        ip = ".".join([str(peers[index + offset]) for offset in range(4)])
        # The port is encoded as a 16-bit big-endian integer.
        # So, we need to multiply the first byte by 256 and add the second byte.
        port = peers[index + 4] * 256 + peers[index + 5]
        result.append(f"{ip}:{port}")
        index += 6
    return result
def get_peer_id(ip, port, info_hash):
    protocol_name_length = struct.pack(">B", 19)
    protocol_name = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    peer_id = b"PC0001-7694471987235"
    payload = (
        protocol_name_length + protocol_name + reserved_bytes + info_hash + peer_id
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, port))
        sock.sendall(payload)
        response = sock.recv(1024)
        return response[48:].hex()
    finally:
        sock.close()


def download_piece(decoded_data, info_hash, piece_index, output_file):
    peers = get_peers(decoded_data, info_hash)
    peer_ip, peer_port = peers[0].split(":")
    peer_port = int(peer_port)
    get_peer_id(peer_ip, peer_port, info_hash)
    protocol_name_length = struct.pack(">B", 19)
    protocol_name = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    peer_id = b"PC0001-7694471987235"
    payload = (
        protocol_name_length + protocol_name + reserved_bytes + info_hash + peer_id
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((peer_ip, peer_port))
        sock.sendall(payload)
        response = sock.recv(68)
        message = receive_message(sock)
        while int(message[4]) != 5:
            message = receive_message(sock)
        interested_payload = struct.pack(">IB", 1, 2)
        sock.sendall(interested_payload)
        message = receive_message(sock)
        while int(message[4]) != 1:
            message = receive_message(sock)
        file_length = decoded_data["info"]["length"]
        total_number_of_pieces = len(
            extract_pieces_hashes(decoded_data["info"]["pieces"])
        )
        default_piece_length = decoded_data["info"]["piece length"]
        if piece_index == total_number_of_pieces - 1:
            piece_length = file_length - (default_piece_length * piece_index)
        else:
            piece_length = default_piece_length
        number_of_blocks = math.ceil(piece_length / (16 * 1024))
        data = bytearray()
        for block_index in range(number_of_blocks):
            begin = 2**14 * block_index
            print(f"begin: {begin}")
            block_length = min(piece_length - begin, 2**14)
            print(
                f"Requesting block {block_index + 1} of {number_of_blocks} with length {block_length}"
            )
            request_payload = struct.pack(
                ">IBIII", 13, 6, piece_index, begin, block_length
            )
            print("Requesting block, with payload:")
            print(request_payload)
            print(struct.unpack(">IBIII", request_payload))
            print(int.from_bytes(request_payload[:4]))
            print(int.from_bytes(request_payload[4:5]))
            print(int.from_bytes(request_payload[5:9]))
            print(int.from_bytes(request_payload[17:21]))
            sock.sendall(request_payload)
            message = receive_message(sock)
            data.extend(message[13:])
        with open(output_file, "wb") as f:
            f.write(data)
    finally:
        sock.close()
    return True
def receive_message(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    # If we didn't receive the full message for some reason, keep gobbling.
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message

def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(bytes_to_str(decode_bencode(bencoded_value))))
    elif command == "info":
        torrent_file_path = sys.argv[2]
        with open(torrent_file_path, "rb") as file:
            bencoded_data = file.read()
            decoded_data = decode_bencode(bencoded_data)
            #data = bytes_to_str(decoded_data)
            tracker_url = decoded_data[b"announce"].decode()
            length = decoded_data[b"info"][b"length"]
            info_dict = decoded_data[b"info"]
            bencoded_info = bencodepy.encode(info_dict)
            info_hash = hashlib.sha1(bencoded_info).hexdigest()
            print(f"Tracker URL: {tracker_url}")
            print(f"Length: {length}")
            print(f"Info Hash: {info_hash}")
            print(f'Piece Length: {decoded_data[b"info"][b"piece length"]}')
            print(f"Piece Hashes: ")
            for i in range(0, len(decoded_data[b"info"][b"pieces"]), 20):
                print(decoded_data[b"info"][b"pieces"][i : i + 20].hex())
    elif command == "peers":
        with open(sys.argv[2], "rb") as f:
            bencoded_value = f.read()
            decoded_data = decode_bencode(bencoded_value)
            tracker_url = decoded_data[b"announce"].decode()
            info_dict = decoded_data[b"info"]
            bencoded_info = bencodepy.encode(info_dict)
            info_hash = hashlib.sha1(bencoded_info).digest()
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
            for i in range(0, len(peers), 6):
                ip = ".".join(str(b) for b in peers[i : i + 4])
                port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
                print(f"Peer: {ip}:{port}")
    elif command == "handshake":
        file_name = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")
        with open(file_name, "rb") as file:
            parsed = decode_bencode(file.read())
            info = parsed[b"info"]
            bencoded_info = bencodepy.encode(info)
            info_hash = hashlib.sha1(bencoded_info).digest()
            handshake = (
                b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
                + info_hash
                + b"IloveQBitTorrent2030"
            )
            # make request to peer
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, int(port)))
                s.send(handshake)
                print(f"Peer ID: {s.recv(68)[48:].hex()}")
    elif command == "download_piece":
        output_file = sys.argv[3]
        piece_index = int(sys.argv[5])
        torrent_file = sys.argv[4]
        with open(torrent_file, "rb") as f:
            torrent_data = f.read()
            decoded_data = decode_bencode(torrent_data)[0]
            if download_piece(
                decoded_data,
                hashlib.sha1(extract_info_hash(torrent_data)).digest(),
                piece_index,
                output_file,
            ):
                print(f"Piece {piece_index} downloaded to {output_file}.")
            else:
                raise RuntimeError("Failed to download piece")

    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
