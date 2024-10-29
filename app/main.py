import json
import sys
import bencodepy
import hashlib
import struct
import requests

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
        torrent_info, _ = decode_bencode(bencoded_value)
        tracker_url = torrent_info.get("announce", "").decode()
        info_dict = torrent_info.get("info", {})
        bencoded_info = bytes_to_str(info_dict)
        info_hash = hashlib.sha1(bencoded_info).digest()
        params = {
            "info_hash": info_hash,
            "peer_id": "00112233445566778899",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": torrent_info.get("info", {}).get("length", 0),
            "compact": 1,
        }
        response = requests.get(tracker_url, params=params)
        response_dict, _ = decode_bencode(response.content)
        peers = response_dict.get("peers", b"")
        for i in range(0, len(peers), 6):
            ip = ".".join(str(b) for b in peers[i : i + 4])
            port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
            print(f"Peer: {ip}:{port}")
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
