import json
import sys
import bencodepy
import hashlib
import struct
import math
import socket
import requests
import os
from urllib.parse import unquote

def decode_bencode(bencoded_value):
    return bencodepy.decode(bencoded_value)

def url_encode(info_hash):
    split_string = ''.join(['%' + info_hash[i:i+2] for i in range(0,len(info_hash),2)])
    return split_string

def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    elif isinstance(data, dict):
        return {bytes_to_str(key): bytes_to_str(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [bytes_to_str(item) for item in data]
    else:
        return data

def integer_to_byte(integer):
    return struct.pack('>I', integer)

def byte_to_integer(byte):
    return struct.unpack('>I', byte)[0]

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

def parse_magnet_link(magnet_link):
    query_params = magnet_link[8:].split("&")
    params = dict()
    for p in query_params:
        key, value = p.split("=")
        params[key] = value
    info_hash = params["xt"][9:]
    tracker_url = unquote(params["tr"])
    print(f"Tracker URL: {tracker_url}")
    print(f"Info Hash: {info_hash}")
    return tracker_url, info_hash


def ping_peer_magnet(peer_ip, peer_port, info_hash, peer_id, s):
    info_hash = bytes.fromhex(info_hash)
    s.connect((peer_ip,peer_port))
        
    protocol_length = 19
    protocol_length_bytes = protocol_length.to_bytes(1,byteorder='big')
    s.sendall(protocol_length_bytes)
    
    message = 'BitTorrent protocol'
    s.sendall(message.encode('utf-8'))
    
    reserved_bytes = b'\x00\x00\x00\x00\x00\x10\x00\x00'
    s.sendall(reserved_bytes)
    
    s.sendall(info_hash)
    
    s.sendall(peer_id.encode('utf-8'))
    
    s.recv(1)
    s.recv(19)
    s.recv(8)
    s.recv(20)
    return s.recv(20).hex()

def get_peer_address_magnet(url, sha_info_hash):  
    encoded_hash = url_encode(sha_info_hash)
    peer_id = 'IloveQBitTorrent2030'
    port = 6881
    uploaded = 0
    downloaded = 0
    left = 999
    compact = 1
    
    query_string = (
        f"info_hash={encoded_hash}&"
        f"peer_id={peer_id}&"
        f"port={port}&"
        f"uploaded={uploaded}&"
        f"downloaded={downloaded}&"
        f"left={left}&"
        f"compact={compact}"
    )
    
    complete_url = f"{url}?{query_string}"
    r = requests.get(complete_url)
    decoded_dict  = decode_bencode(r.content)
    peers = decoded_dict[b"peers"]
    decimal_values = [byte for byte in peers]
    
    ip_address_list = []
    for i in range(0,len(decimal_values),6):
        ip_address = '.'.join(str(num) for num in decimal_values[i:i+4])
        ip_address += f":{int.from_bytes(decimal_values[i+4:i+6], byteorder='big', signed=False)}"
        ip_address_list.append(ip_address)
     
    return ip_address_list

def handle_magnet_handshake(magnet_link):
    info_hash_location = magnet_link.find("btih:") + 5
    info_hash = magnet_link[info_hash_location : info_hash_location + 40]
    url_location = magnet_link.find("tr=") + 3
    url = unquote(magnet_link[url_location:])
    ip_addresses = get_peer_address_magnet(url, info_hash)
    peer_ip, peer_port = ip_addresses[0].split(":")
    peer_port = int(peer_port)
    peer_id = "ILoveQBitTorrent2030"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    response_peer_id = ping_peer_magnet(peer_ip, peer_port, info_hash, peer_id, s)
    print(f"Peer ID: {response_peer_id}")
    # Bitfield
    s.recv(4)
    s.recv(1)
    s.recv(4)
    magnet_dict = {"m": {"ut_metadata": 18}}
    encoded_magnet_dict = bencodepy.encode(magnet_dict)
    s.sendall(integer_to_byte(len(encoded_magnet_dict) + 2))
    s.sendall(b"\x14")
    s.sendall(b"\x00")
    s.sendall(encoded_magnet_dict)
    payload_size = byte_to_integer(s.recv(4)) - 2
    s.recv(1)
    s.recv(1)
    s.recv(payload_size)


    msg = receive_message(s)
    print(msg)
    dic = decode_bencode(msg[2:])
    print(f"receive dict {dic}")
    print(f"Peer Metadata Extension ID: {dic[b"m"][b"ut_metadata"]}")


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
    elif command == "magnet_parse":
        parse_magnet_link(sys.argv[2])
    elif command == "magnet_handshake":
        handle_magnet_handshake(sys.argv[2])
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()



import json
import sys
import hashlib
import bencodepy
import requests
import struct
import socket
import math
import random
import string
import threading
from queue import Queue
import urllib.parse
import time

bc = bencodepy.Bencode(encoding="utf-8")

def decode_bencode(bencoded_value):
    return bc.decode(bencoded_value)

def bytes_to_str(data):
    """Converts bytes to strings or recursively converts elements in lists/dictionaries."""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    elif isinstance(data, list):
        return [bytes_to_str(item) for item in data]
    elif isinstance(data, dict):
        return {bytes_to_str(k): bytes_to_str(v) for k, v in data.items()}
    return data

def recv_message(sock):
    try:
        # Receive the 4-byte message length prefix
        length_prefix = sock.recv(4)
        if not length_prefix or len(length_prefix) < 4:
            raise ConnectionError("Failed to receive message length prefix.")
        # Convert the length prefix to an integer
        message_length = int.from_bytes(length_prefix)
        print(f"Received message length: {message_length}")
        if message_length <= 0:
            raise ValueError("Received invalid message length.")
        # Initialize buffer for the incoming message
        message = b""
        while len(message) < message_length:
            # Receive in chunks until the full message is acquired
            chunk = sock.recv(
                min(4096, message_length - len(message))
            )  # Read up to 4096 bytes per iteration
            if not chunk:
                raise ConnectionError(
                    "Connection closed before full message was received."
                )
            message += chunk
        # Return the full message with the length prefix included
        return length_prefix + message
    except Exception as e:
        print(f"Error receiving message: {e}")
        return None
    
def extract_pieces_hashes(pieces_hashes):
    index, result = 0, []
    while index < len(pieces_hashes):
        result.append(pieces_hashes[index : index + 20].hex())
        index += 20
    return result

def download_piece(sock, piece_index, decoded_data):
    # Extract necessary information from the decoded torrent file
    # if exisst info key in decoded_data
    if decoded_data.get(b"info") is not None:
        file_length = decoded_data[b"info"][b"length"]
        total_number_of_pieces = len(
            extract_pieces_hashes(decoded_data[b"info"][b"pieces"])
        )
        default_piece_length = decoded_data[b"info"][b"piece length"]
    else:
        file_length = decoded_data[b"length"]
        default_piece_length = decoded_data[b"piece length"]
        total_number_of_pieces = len(extract_pieces_hashes(decoded_data[b"pieces"]))
    # Determine the piece length for the current piece
    if piece_index == total_number_of_pieces - 1:
        # Last piece may be shorter than the default piece length
        piece_length = file_length - (default_piece_length * piece_index)
    else:
        # Use the default piece length for non-final pieces
        piece_length = default_piece_length
    # Calculate the number of blocks in this piece
    block_size = 16 * 1024  # 16 KB block size
    number_of_blocks = math.ceil(piece_length / block_size)
    # Initialize a variable to hold the received piece data
    piece_data = b""
    # Request each block of the piece from the peer
    for block_num in range(number_of_blocks):
        block_offset = block_num * block_size
        block_len = min(block_size, piece_length - block_offset)
        # Pack the request message (13 bytes: length prefix, message ID, piece index, block offset, block length)
        request_message = struct.pack(
            ">IbIII", 13, 6, piece_index, block_offset, block_len
        )
        sock.send(request_message)
        # Receive the piece message (message ID 7)
        message = recv_message(sock)
        while message[4] != 7:  # Wait for a "piece" message (ID 7)
            message = recv_message(sock)
        # The first 13 bytes are the message prefix and index; the rest is the block data
        block_data = message[13:]
        piece_data += block_data
        print(
            f"Received block {block_num + 1}/{number_of_blocks} for piece {piece_index}"
        )
    return piece_data

def get_peers(info_hash, decoded_content):
    """Retrieve a list of peers from the tracker."""
    params = {
        "info_hash": info_hash,
        "peer_id": "00112233445566778899",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": decoded_content["info"]["length"],
        "compact": 1,
    }
    response = requests.get(decoded_content["announce"], params=params)
    response_content = bencodepy.decode(response.content)
    peers = response_content.get(b"peers", b"")
    peer_list = []
    for i in range(0, len(peers), 6):
        ip = ".".join(str(b) for b in peers[i : i + 4])
        port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
        peer_list.append((ip, port))
    return peer_list

def get_peers_real(info_hash, decoded_content, peer_id, port):
    """Retrieve a list of peers from the tracker."""
    params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": port,
        "uploaded": 0,
        "downloaded": 0,
        "left": decoded_content["info"]["length"],
        "left": decoded_content["info"]["length"]
        if decoded_content.get("info") is not None
        else decoded_content["length"],
        "compact": 1,
    }
    response = requests.get(decoded_content["announce"], params=params)
    response_content = bencodepy.decode(response.content)
    peers = response_content.get(b"peers", b"")
    peer_list = []
    for i in range(0, len(peers), 6):
        ip = ".".join(str(b) for b in peers[i : i + 4])
        port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
        peer_list.append((ip, port))
    return peer_list

def verify_piece(piece_data, expected_hash):
    piece_hash = hashlib.sha1(piece_data).digest()
    return piece_hash == expected_hash

def generate_peer_id():
    """Generate a unique 20-byte peer ID."""
    base_peer_id = "-BT0001-"  # Example: BT for BitTorrent, 0001 for version 1
    unique_suffix = "".join(
        random.choices(string.ascii_letters + string.digits, k=12)
    )  # Random 12 characters
    return (base_peer_id + unique_suffix).encode("utf-8")

def ping_peer(ip, port):
    """Measure latency by attempting to connect and performing a quick handshake."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Set a timeout for connection
            start_time = time.time()
            s.connect((ip, port))
            end_time = time.time()
            s.close()
            return end_time - start_time  # Latency in seconds
    except Exception:
        return float("inf")  # Return infinity if the peer is unreachable
    
def choose_best_peer(peers, info_hash, peer_id):
    """Choose the best peer based on latency and available pieces."""
    peer_latencies = []
    for ip, port in peers:
        latency = ping_peer(ip, port)
        if latency < float("inf"):
            peer_latencies.append((latency, ip, port))
    if not peer_latencies:
        return None  # No reachable peers
    # Sort peers by latency (lower is better)
    peer_latencies.sort(key=lambda x: x[0])
    # Return the best peer (the one with the lowest latency)
    return peer_latencies[0][1], peer_latencies[0][2]

def download_worker(piece_queue, info_hash, parsed, output_file, worker_id):
    while not piece_queue.empty():
        piece_index = piece_queue.get()
        peer_id = generate_peer_id()
        port = 6881 + worker_id
        # Retrieve peers
        peers = get_peers_real(info_hash, bytes_to_str(parsed), peer_id.decode(), port)
        if not peers:
            print(f"No peers available for piece {piece_index}")
            piece_queue.put(piece_index)  # Add back to queue
            return
        # Use a vailible
        ip, port = choose_best_peer(peers, info_hash, peer_id.decode())
        print(
            f"Worker {worker_id} connecting to peer {ip}:{port} for piece {piece_index}"
        )
        handshake = (
            b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
            + info_hash
            + peer_id
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                s.send(handshake)
                print(f"Peer ID: {s.recv(68)[48:].hex()}")
                # Receive bitfield message from the peer
                message = recv_message(s)
                while message[4] != 5:
                    message = recv_message(s)
                print(f"Received bitfield message: {message[1:]}")
                # Send interested message
                interested_message = struct.pack(">Ib", 1, 2)
                s.send(interested_message)
                print("Sent interested message")
                # Wait for unchoke message (ID 1)
                message = recv_message(s)
                while int(message[4]) != 1:
                    message = recv_message(s)
                # Download the piece
                piece_data = download_piece(s, piece_index, parsed)
                # Verify the piece's integrity
                piece_hashes = extract_pieces_hashes(parsed[b"info"][b"pieces"])
                if verify_piece(piece_data, bytes.fromhex(piece_hashes[piece_index])):
                    print(f"Piece {piece_index} verified successfully.")
                    with open(output_file, "r+b") as f:
                        piece_length = parsed[b"info"][b"piece length"]
                        f.seek(piece_index * piece_length)
                        f.write(piece_data)
                else:
                    print(f"Piece {piece_index} failed verification.")
                    piece_queue.put(piece_index)  # Add back to queue for retry
        except Exception as e:
            print(
                f"Failed to download piece {piece_index} from peer {ip}:{port}. Error: {e}"
            )
            piece_queue.put(piece_index)  # Add back to queue
        piece_queue.task_done()
def download_torrent(torrent_file_path, output_file, num_workers=4):
    # Read the torrent file and get piece information
    with open(torrent_file_path, "rb") as file:
        parsed = bencodepy.decode(file.read())
        decoded_data = bytes_to_str(parsed)
    info = parsed[b"info"]
    piece_length = info[b"piece length"]
    total_length = info[b"length"]
    piece_hashes = extract_pieces_hashes(info[b"pieces"])
    # Prepare the output file
    with open(output_file, "wb") as f:
        f.truncate(total_length)
    # Create a queue of pieces to download
    piece_queue = Queue()
    for piece_index in range(len(piece_hashes)):
        piece_queue.put(piece_index)
    # Create multiple workers to download pieces
    info_hash = hashlib.sha1(bencodepy.encode(info)).digest()
    threads = []
    for _ in range(num_workers):
        t = threading.Thread(
            target=download_worker,
            args=(piece_queue, info_hash, parsed, output_file, _),
        )
        t.start()
        threads.append(t)
    # Wait for all threads to complete
    piece_queue.join()
    for t in threads:
        t.join()
    print(f"File downloaded and saved to {output_file}")
def parse_magnet(magnet_link):
    # Parse the magnet link
    if not magnet_link.startswith("magnet:?"):
        raise ValueError("Invalid magnet link format")
    # Extract query parameters from the magnet link
    query = urllib.parse.urlparse(magnet_link).query
    params = urllib.parse.parse_qs(query)
    # Extract necessary components
    xt = params.get("xt", [None])[0]  # urn:btih: followed by the info hash
    dn = params.get("dn", [None])[0]  # The display name
    tr = params.get("tr", [None])[0]  # The tracker URL
    # Ensure we have an info hash (xt)
    if not xt or not xt.startswith("urn:btih:"):
        raise ValueError("Magnet link must include an info hash (xt)")
    # Extract the info hash from xt
    info_hash = xt.split(":")[-1]
    # Return extracted data
    return tr, info_hash, dn
def set_extension_bit_reserved_bytes():
    """Set the 20th bit from the right to 1 in the reserved bytes."""
    reserved_bytes = bytearray(8)
    reserved_bytes[
        5
    ] = 0x10  # 0x10 is 00010000 in binary, which sets the 20th bit from the right
    return bytes(reserved_bytes)
def send_extension_handshake(sock):
    """Send the extension handshake to a peer, indicating support for 'ut_metadata'."""
    # Construct the extension handshake message
    extension_id = 1  # Choose an ID for 'ut_metadata' between 1 and 255
    handshake_message = {"m": {"ut_metadata": extension_id}}
    # Bencode the handshake message
    bencoded_handshake = bencodepy.encode(handshake_message)
    # Prepare the extension handshake payload
    message_length = (
        len(bencoded_handshake) + 2
    )  # 1 byte for message ID, 1 byte for extension message ID
    message_id = 20  # All extension messages use ID 20
    extension_message_id = 0  # 0 for extension handshake
    payload = (
        struct.pack(">Ib", message_length, message_id)
        + struct.pack("B", extension_message_id)
        + bencoded_handshake
    )
    # Send the extension handshake
    sock.send(payload)
    print("Sent extension handshake with 'ut_metadata' support")

def receive_extension_handshake(sock):
    """Receive and decode the extension handshake from the peer."""
    # Receive the extension handshake message
    message = recv_message(sock)
    while message[4] != 20:  # Wait for the extension handshake message (ID 20)
        message = recv_message(sock)
    # Extract the extension message ID and payload
    extension_message_id = message[5]
    payload = message[6:]
    # Decode the payload to get the 'ut_metadata' ID
    decoded_payload = bencodepy.decode(payload)
    ut_metadata_id = decoded_payload[b"m"][b"ut_metadata"]
    print(f"Received extension handshake with 'ut_metadata' ID: {ut_metadata_id}")
    print(f"Peer Metadata Extension ID: {ut_metadata_id}")
    return ut_metadata_id

def magnet_handshake(magnet_link):
    # Parse the magnet link to get info_hash and tracker URL
    tracker_url, info_hash, _ = parse_magnet(magnet_link)
    # Get the list of peers from the tracker
    peers = get_peers_real(
        bytes.fromhex(info_hash),
        {"announce": tracker_url, "info": {"length": 999}},
        generate_peer_id().decode(),
        6881,
    )
    if not peers:
        print("No peers available.")
        return
    # Use the first peer from the list
    ip, port = peers[0]
    print(f"Connecting to peer {ip}:{port}")
    # Perform handshake with extension support
    peer_id = generate_peer_id()
    reserved_bytes = set_extension_bit_reserved_bytes()
    # Create the handshake message
    handshake = (
        b"\x13BitTorrent protocol" + reserved_bytes + bytes.fromhex(info_hash) + peer_id
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.send(handshake)
            # Receive the handshake response (68 bytes expected)
            response = s.recv(68)
            if len(response) < 68:
                print("Invalid handshake response.")
                return
            # Extract the peer ID from the response (last 20 bytes)
            received_peer_id = response[48:].hex()
            print(f"Peer ID: {received_peer_id}")
            # Bitfield message
            message = recv_message(s)
            while message[4] != 5:
                message = recv_message(s)
            print(f"Received bitfield message: {message[1:]}")
            # Check if the peer supports extensions
            if response[25] & 0x10:  # Check if the 20th bit from the right is set
                print("Peer supports extensions, sending extension handshake...")
                send_extension_handshake(s)
                # Receive the response to the extension handshake and get the 'ut_metadata' ID
                ut_metadata_id = receive_extension_handshake(s)
    except Exception as e:
        print(f"Error during handshake with peer {ip}:{port}. Error: {e}")

def send_metadata_request(sock, metadata_id):
    """Send the metadata request to a peer."""
    # Construct the bencoded dictionary for the request
    request_dict = {"msg_type": 0, "piece": 0}
    bencoded_request = bencodepy.encode(request_dict)
    # Calculate the length prefix: 1 byte for extension message ID, rest for the bencoded request
    message_length = (
        len(bencoded_request) + 2
    )  # 1 byte for message ID (20), 1 byte for extension message ID
    # Construct the metadata request message
    message_id = 20  # Extension message ID for metadata extension
    payload = (
        struct.pack(">Ib", message_length, message_id)
        + struct.pack("B", metadata_id)
        + bencoded_request
    )
    # Send the metadata request
    sock.send(payload)
    print("Sent metadata request (msg_type: 0)")

def receive_metadata_data(sock, metadata_id):
    """Receive the metadata data message from the peer."""
    try:
        # Wait for the data message response
        message = sock.recv(4096)
        if not message:
            raise ConnectionError("Failed to receive metadata data message.")
        if len(message) < 6:
            raise ValueError("Received message is too short.")
        if message[4] != 20:
            raise ValueError("Received an unexpected message type.")
        bencoded_dict = message[6:]
        # Look for the end of the bencoded dictionary, which should end with 'ee'
        bencoded_end_index = bencoded_dict.find(b"ee") + 2  # Include the 'ee' ending
        # Decode the bencoded part
        decoded_message = bencodepy.decode(bencoded_dict[:bencoded_end_index])
        # Ensure it's a data message
        if decoded_message.get(b"msg_type") != 1:
            raise ValueError("Received an unexpected message type.")
        # Extract metadata information
        total_size = decoded_message.get(b"total_size", 0)
        piece_index = decoded_message.get(b"piece", 0)
        # The raw metadata piece starts right after the bencoded dictionary
        metadata_piece = bencoded_dict[bencoded_end_index:]
        print(f"Received metadata piece of size {total_size} bytes.")
        return metadata_piece
    except Exception as e:
        print(f"Error receiving metadata data: {e}")

def extract_torrent_info(metadata_piece, info_hash):
    """Extract torrent info from the metadata piece and validate against the info hash."""
    try:
        # Decode the metadata piece to get the info dictionary
        info_dict = bencodepy.decode(metadata_piece)
        # Compute SHA-1 hash of the info dictionary
        computed_info_hash = hashlib.sha1(bencodepy.encode(info_dict)).hexdigest()
        # Validate the hash
        if computed_info_hash != info_hash:
            raise ValueError(
                "Computed info hash does not match the expected info hash."
            )
        # Extract torrent details
        piece_length = info_dict[b"piece length"]
        pieces = info_dict[b"pieces"]
        file_name = info_dict[b"name"]
        file_length = info_dict[b"length"]
        # Extract individual piece hashes
        piece_hashes = [pieces[i : i + 20].hex() for i in range(0, len(pieces), 20)]
        # Display information
        print(f"Length: {file_length}")
        print(f"Info Hash: {computed_info_hash}")
        print(f"Piece Length: {piece_length}")
        print("Piece Hashes:")
        for piece_hash in piece_hashes:
            print(piece_hash)
    except Exception as e:
        print(f"Error extracting torrent info: {e}")

def magnet_info(magnet_link):
    # Parse the magnet link to get info_hash and tracker URL
    tracker_url, info_hash, _ = parse_magnet(magnet_link)
    print(f"Tracker URL: {tracker_url}")
    # Get the list of peers from the tracker
    peers = get_peers_real(
        bytes.fromhex(info_hash),
        {"announce": tracker_url, "info": {"length": 999}},
        generate_peer_id().decode(),
        6881,
    )
    if not peers:
        print("No peers available.")
        return
    # Use the first peer from the list
    ip, port = peers[0]
    print(f"Connecting to peer {ip}:{port}")
    # Perform handshake with extension support
    peer_id = generate_peer_id()
    reserved_bytes = set_extension_bit_reserved_bytes()
    # Create the handshake message
    handshake = (
        b"\x13BitTorrent protocol" + reserved_bytes + bytes.fromhex(info_hash) + peer_id
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.send(handshake)
            # Receive the handshake response (68 bytes expected)
            response = s.recv(68)
            if len(response) < 68:
                print("Invalid handshake response.")
                return
            # Bitfiled message
            message = recv_message(s)
            while message[4] != 5:
                message = recv_message(s)
            # Check if the peer supports extensions
            if response[25] & 0x10:  # Check if the 20th bit from the right is set
                print("Peer supports extensions, sending extension handshake...")
                send_extension_handshake(s)
                # Receive the response to the extension handshake and get the 'ut_metadata' ID
                metadata_id = receive_extension_handshake(s)
                # Send metadata request (msg_type: 0)
                send_metadata_request(s, metadata_id)
                # For this stage, no additional output is required.
                # Receive the metadata data message (msg_type: 1)
                metadata_piece = receive_metadata_data(s, metadata_id)
                # Validate and extract information from metadata
                if metadata_piece:
                    extract_torrent_info(metadata_piece, info_hash)
    except Exception as e:
        print(f"Error during handshake with peer {ip}:{port}. Error: {e}")

def magnet_download_piece(output_file, magnet_link, piece_index):
    try:
        # Parse the magnet link to get the tracker URL and info hash
        tracker_url, info_hash, _ = parse_magnet(magnet_link)
        # Get the list of peers from the tracker
        peers = get_peers_real(
            bytes.fromhex(info_hash),
            {"announce": tracker_url, "info": {"length": 999}},
            generate_peer_id().decode(),
            6881,
        )
        if not peers:
            print("No peers available.")
            return
        # Use the best peer
        ip, port = choose_best_peer(
            peers, bytes.fromhex(info_hash), generate_peer_id().decode()
        )
        print(f"Connecting to peer {ip}:{port}")
        # Perform the handshake with extension support
        peer_id = generate_peer_id()
        reserved_bytes = set_extension_bit_reserved_bytes()
        handshake = (
            b"\x13BitTorrent protocol"
            + reserved_bytes
            + bytes.fromhex(info_hash)
            + peer_id
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.send(handshake)
            # Receive the handshake response
            response = s.recv(68)
            if len(response) < 68:
                print("Invalid handshake response.")
                return
            # bitfield message
            message = recv_message(s)
            while message[4] != 5:
                message = recv_message(s)
            print(f"Received bitfield message: {message[1:]}")
            # Check if the peer supports extensions
            if response[25] & 0x10:
                print("Peer supports extensions, sending extension handshake...")
                send_extension_handshake(s)
                # Receive the response to the extension handshake and get the 'ut_metadata' ID
                metadata_id = receive_extension_handshake(s)
                # Send metadata request (msg_type: 0)
                send_metadata_request(s, metadata_id)
                # Receive the metadata data message (msg_type: 1)
                metadata_piece = receive_metadata_data(s, metadata_id)
                # Validate and extract information from metadata
                if metadata_piece:
                    parsed_metadata = bencodepy.decode(metadata_piece)
                    piece_length = parsed_metadata[b"piece length"]
                    file_length = parsed_metadata[b"length"]
                    # Download the specified piece
                    print(f"Downloading piece {piece_index}")
                    # send interested message
                    interested_message = struct.pack(">Ib", 1, 2)
                    s.send(interested_message)
                    print("Sent interested message")
                    # wait for unchoke message
                    message = recv_message(s)
                    while int(message[4]) != 1:
                        message = recv_message(s)
                    piece_data = download_piece(s, piece_index, parsed_metadata)
                    # Verify the downloaded piece
                    piece_hashes = extract_pieces_hashes(parsed_metadata[b"pieces"])
                    if verify_piece(
                        piece_data, bytes.fromhex(piece_hashes[piece_index])
                    ):
                        print(f"Piece {piece_index} verified successfully.")
                        with open(output_file, "wb") as f:
                            f.write(piece_data)
                        print(
                            f"Piece {piece_index} downloaded and saved to {output_file}"
                        )
                    else:
                        print(f"Piece {piece_index} failed verification.")
            else:
                print("Peer does not support metadata extensions.")
    except Exception as e:
        print(f"Error during piece download from magnet link. Error: {e}")

def download_worker_magnet(piece_queue, info_hash, parsed_metadata, output_file, worker_id):
    peer_id = generate_peer_id()
    port = 6881 + worker_id  # Use a different port for each worker
    while not piece_queue.empty():
        piece_index = piece_queue.get()
        # Retrieve peers
        peers = get_peers_real(
            info_hash, bytes_to_str(parsed_metadata), peer_id.decode(), port
        )
        if not peers:
            print(f"No peers available for piece {piece_index}")
            piece_queue.put(piece_index)  # Add back to queue for retry
            continue
        # Choose the best peer
        ip, port = choose_best_peer(peers, info_hash, peer_id.decode())
        print(
            f"Worker {worker_id} connecting to peer {ip}:{port} for piece {piece_index}"
        )
        # Construct the handshake message
        reserved_bytes = set_extension_bit_reserved_bytes()
        handshake = b"\x13BitTorrent protocol" + reserved_bytes + info_hash + peer_id
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                s.send(handshake)
                # Receive the handshake response
                response = s.recv(68)
                if len(response) < 68:
                    print("Invalid handshake response.")
                    piece_queue.put(piece_index)  # Add back to queue
                    continue
                # Check if the peer supports extensions
                if response[25] & 0x10:
                    send_extension_handshake(s)
                    metadata_id = receive_extension_handshake(s)
                    # Send metadata request
                    send_metadata_request(s, metadata_id)
                    # Receive and decode metadata
                    metadata_piece = receive_metadata_data(s, metadata_id)
                    if metadata_piece:
                        piece_length = parsed_metadata[b"piece length"]
                        piece_hashes = extract_pieces_hashes(parsed_metadata[b"pieces"])
                        # Download the specified piece
                        print(f"Downloading piece {piece_index} from peer {ip}:{port}")
                        # Send interested message
                        interested_message = struct.pack(">Ib", 1, 2)
                        s.send(interested_message)
                        print("Sent interested message")
                        # Wait for unchoke message (ID 1)
                        message = recv_message(s)
                        while int(message[4]) != 1:
                            message = recv_message(s)
                        # Download the piece
                        piece_data = download_piece(s, piece_index, parsed_metadata)
                        # Verify the piece's integrity
                        if verify_piece(
                            piece_data, bytes.fromhex(piece_hashes[piece_index])
                        ):
                            print(
                                f"Piece {piece_index} verified successfully by worker {worker_id}."
                            )
                            with open(output_file, "r+b") as f:
                                piece_length = parsed_metadata[b"piece length"]
                                f.seek(piece_index * piece_length)
                                f.write(piece_data)
                        else:
                            print(
                                f"Piece {piece_index} failed verification by worker {worker_id}."
                            )
                            piece_queue.put(piece_index)  # Add back to queue for retry
                else:
                    print("Peer does not support metadata extensions.")
                    piece_queue.put(piece_index)  # Retry with another peer
        except Exception as e:
            print(
                f"Worker {worker_id} failed to download piece {piece_index} from peer {ip}:{port}. Error: {e}"
            )
            piece_queue.put(piece_index)  # Add back to queue for retry
        piece_queue.task_done()

def magnet_download(output_file, magnet_link, num_workers=4):
    # Step 1: Parse the magnet link to get tracker URL and info hash
    # delete "" from magnet_link
    print(magnet_link)
    tracker_url, info_hash, _ = parse_magnet(magnet_link)
    # Step 2: Get the list of peers from the tracker
    peers = get_peers_real(
        bytes.fromhex(info_hash),
        {"announce": tracker_url, "info": {"length": 999}},
        generate_peer_id().decode(),
        6881,
    )
    if not peers:
        print("No peers available.")
        return
    # Step 3: Choose a peer to get metadata
    ip, port = choose_best_peer(
        peers, bytes.fromhex(info_hash), generate_peer_id().decode()
    )
    print(f"Connecting to peer {ip}:{port} to fetch metadata")
    peer_id = generate_peer_id()
    reserved_bytes = set_extension_bit_reserved_bytes()
    handshake = (
        b"\x13BitTorrent protocol" + reserved_bytes + bytes.fromhex(info_hash) + peer_id
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.send(handshake)
            # Receive the handshake response
            response = s.recv(68)
            if len(response) < 68:
                print("Invalid handshake response.")
                return
            # Check if the peer supports extensions
            if response[25] & 0x10:
                send_extension_handshake(s)
                metadata_id = receive_extension_handshake(s)
                # Request metadata
                send_metadata_request(s, metadata_id)
                metadata_piece = receive_metadata_data(s, metadata_id)
                # Validate and extract information from metadata
                if metadata_piece:
                    parsed_metadata = bencodepy.decode(metadata_piece)
                    piece_length = parsed_metadata[b"piece length"]
                    total_length = parsed_metadata[b"length"]
                    piece_hashes = extract_pieces_hashes(parsed_metadata[b"pieces"])
                    parsed_metadata[b"announce"] = tracker_url.encode("utf-8")
                    # Prepare the output file
                    with open(output_file, "wb") as f:
                        f.truncate(total_length)
                    # Create a queue of pieces to download
                    piece_queue = Queue()
                    for piece_index in range(len(piece_hashes)):
                        piece_queue.put(piece_index)
                    # Start multiple workers to download pieces
                    threads = []
                    for worker_id in range(num_workers):
                        t = threading.Thread(
                            target=download_worker_magnet,
                            args=(
                                piece_queue,
                                bytes.fromhex(info_hash),
                                parsed_metadata,
                                output_file,
                                worker_id,
                            ),
                        )
                        t.start()
                        threads.append(t)
                    # Wait for all threads to complete
                    piece_queue.join()
                    for t in threads:
                        t.join()
                    print(f"File downloaded and saved to {output_file}")
            else:
                print("Peer does not support metadata extensions.")
    except Exception as e:
        print(f"Error during magnet download. Error: {e}")

def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        decoded_value = decode_bencode(bencoded_value)
        print(json.dumps(decoded_value, default=bytes_to_str))
    elif command == "info":
        torrent_file_path = sys.argv[2]
        with open(torrent_file_path, "rb") as file:
            content = file.read()
        decoded_content = bencodepy.decode(content)
        info = bytes_to_str(decoded_content)
        info_hash = hashlib.sha1(bencodepy.encode(decoded_content[b"info"])).hexdigest()
        print(f'Tracker URL: {info["announce"]}')
        print(f'Length: {info["info"]["length"]}')
        print(f"Info Hash: {info_hash}")
        print(f'Piece Length: {info["info"]["piece length"]}')
        print("Piece Hashes:")
        for i in range(0, len(decoded_content[b"info"][b"pieces"]), 20):
            print(decoded_content[b"info"][b"pieces"][i : i + 20].hex())
    elif command == "peers":
        torrent_file_path = sys.argv[2]
        with open(torrent_file_path, "rb") as file:
            content = file.read()
        decoded_content = bencodepy.decode(content)
        info = bytes_to_str(decoded_content)
        info_hash = hashlib.sha1(bencodepy.encode(decoded_content[b"info"])).digest()
        # Get peers from tracker
        peers = get_peers(info_hash, info)
        for ip, port in peers:
            print(f"Peer: {ip}:{port}")
    elif command == "handshake":
        file_name = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")
        with open(file_name, "rb") as file:
            parsed = bencodepy.decode(file.read())
            info = parsed[b"info"]
            bencoded_info = bencodepy.encode(info)
            info_hash = hashlib.sha1(bencoded_info).digest()
            handshake = (
                b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
                + info_hash
                + b"00112233445566778899"
            )
            # make request to peer
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, int(port)))
                s.send(handshake)
                print(f"Peer ID: {s.recv(68)[48:].hex()}")
    elif command == "download_piece":
        output_file = sys.argv[3]
        torrent_file_path = sys.argv[4]
        piece_index = int(sys.argv[5])
        # Read the torrent file and get piece information
        with open(torrent_file_path, "rb") as file:
            parsed = bencodepy.decode(file.read())
            info = parsed[b"info"]
            piece_length = info[b"piece length"]
            # Calculate total length of the file or last piece size
            total_length = info.get(b"length", piece_length)
            last_piece_size = (
                total_length % piece_length
                if total_length % piece_length != 0
                else piece_length
            )
        # Perform the handshake
        bencoded_info = bencodepy.encode(info)
        info_hash = hashlib.sha1(bencoded_info).digest()
        # Retrieve peers and connect to one
        peers = get_peers(info_hash, bytes_to_str(parsed))
        if not peers:
            print("No peers available.")
            return
        # Use the first peer in the list
        ip, port = peers[0]
        print(f"Connecting to peer {ip}:{port}")
        handshake = (
            b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
            + info_hash
            + b"00112233445566778899"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.send(handshake)
            print(f"Peer ID: {s.recv(68)[48:].hex()}")
            message = recv_message(s)
            while message[4] != 5:
                message = recv_message(s)
            print(f"Received bitfield message: {message[1:]}")
            # interested message
            interested_message = struct.pack(">Ib", 1, 2)
            s.send(interested_message)
            print("Sent interested message")
            message = recv_message(s)
            print(f"Received message: {message}")
            while int(message[4]) != 1:
                message = recv_message(s)
            piece_data = download_piece(s, piece_index, parsed)
            with open(output_file, "wb") as f:
                f.write(piece_data)
            print(f"Piece {piece_index} downloaded and saved to {output_file}")
            # close connection
            s.close()
    elif command == "download":
        if len(sys.argv) != 5:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} download -o output filename"
            )
        torrent_file = sys.argv[4]
        output_file = sys.argv[3]
        num_workers = 64  # Optional: specify number of workers
        download_torrent(torrent_file, output_file, num_workers)
    elif command == "magnet_parse":
        if len(sys.argv) != 3:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} magnet_parse <magnet-link>"
            )
        magnet_link = sys.argv[2]
        try:
            tracker_url, info_hash, file_name = parse_magnet(magnet_link)
            print(f"Tracker URL: {tracker_url}")
            print(f"Info Hash: {info_hash}")
            if file_name:
                print(f"File Name: {file_name}")
        except ValueError as e:
            print(f"Error parsing magnet link: {e}")
    elif command == "magnet_handshake":
        if len(sys.argv) != 3:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} magnet_handshake <magnet-link>"
            )
        magnet_link = sys.argv[2]
        magnet_handshake(magnet_link)
    elif command == "magnet_info":
        if len(sys.argv) != 3:
            raise NotImplementedError(f"Usage: {sys.argv[0]} magnet_info <magnet-link>")
        magnet_link = sys.argv[2]
        magnet_info(magnet_link)
    elif command == "magnet_download_piece":
        if len(sys.argv) != 6:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} magnet_download_piece -o output <magnet-link> <piece-index>"
            )
        output_file = sys.argv[3]
        magnet_link = sys.argv[4]
        piece_index = int(sys.argv[5])
        magnet_download_piece(output_file, magnet_link, piece_index)
    elif command == "magnet_download":
        if len(sys.argv) != 5:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} magnet_download -o output <magnet-link>"
            )
        output_file = sys.argv[3]
        magnet_link = sys.argv[4]
        num_workers = 4
        magnet_download(output_file, magnet_link, num_workers)
    else:
        raise NotImplementedError(f"Unknown command {command}")
    
if __name__ == "__main__":
    main()