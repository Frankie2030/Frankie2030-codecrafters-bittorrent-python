import json
import sys
import bencodepy
import hashlib

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
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
