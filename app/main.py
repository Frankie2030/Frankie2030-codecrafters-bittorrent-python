import json
import sys
import bencodepy

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
            tracker_url = decoded_data[b"announce"].decode("utf-8")
            length = decoded_data[b"info"][b"length"]
            print(f"Tracker URL: {tracker_url}")
            print(f"Length: {length}")
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
