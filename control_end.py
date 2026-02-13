import socket,re
import threading
import os
from datetime import datetime
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 服务器的IP和端口
server_ip = '10.21.196.225'
server_port = 7689

file_save_directory = "./received_files"
online_ips = []  # 用于存储在线 IP
private_key = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCe/ckUUXQxuhh7
Rp9SAiCDhUnZru/RblSOutiPzth8fpI9Uwh9JCd2T8I339oFK2cWf+EKS4pXruJt
CduX7qmUOxuIQsuZJaymkyArAGEYIizqq/ajkWg8EU7Qtx4lAZhPWNVVO7eK9TBT
eE5lFBXzc2NUheD4+1R/K77rYoGr1tNAj1baNXXmVvRIxBGFHaylFSdnsQ7e7vUk
45fYaKs8GfhVqOd4Am6Zi2ZS5Ct9bYt56GFyLYvM5ZntJh5L9NXYJBfmi7KpA0/c
cndgLXzYHijyIEuA2L02Lm4+QWe6Y6pibZ5UAOAqznwCHrWvCBpwzmtMeES5i+99
55vXFDsNAgMBAAECggEAC9vZmvSdYlUjXNSObx89/hlbwgsYk6ozT+cTXpyazKRj
M4RFOpJPCDXYQnMlr6OGX6j/p9UtFy+x71igIrO4PdhvzAjRZ1WmTFFmgZaYZ2Sr
LYDQl3Ax0mMnGg3Ch5eYHPj/Bom6/bgel+c+D6+BGKTHaKdIucGDUq34YlW5Xs/7
ytUJSPk8AmanZUf24D2nuvDXXLrSRPoeZ85lKrBf1Qtx07c62tXLN5P3gAKkGytL
96yiiMWUAb6s81+EE8F9TpVDqM95J53F1T28lg8OVlVzfrUCrBmlvJwI/TmNOOey
jFCcHqwVcA7yGoxP8MtCAW1IG3fhA/QJEFm0XSDJAQKBgQDYxZjZ/ofFpqcAiHjg
VUYrM/Wik6LD8VHVUebQmPs2f2uAOBr/CDTWgCtWMwqnmCg1ixPag9unQCt/80fj
Mx4j6bAOlOYSteiMetkE4fnBYxygf8Ysnx0lmWjZqC7k/MKK7FLRwKg18S85UvrD
7hRcA6wYRkKRC9YuM5nsOT10DQKBgQC7w2MZFCi1JsN1LNNmR6ElhtOyXFp95SzF
BIb46rCiFL23OgBpjYCiCwrTcPos2kqNbx6RaPCCJEppQyzoMYPGtKVHNC5/M0Z4
El9P3FFGT2AznH80i1S4DjfcWKpws41htZh6hb7cNIxb/hSI8RVS5mi4tvKhFS2k
rP6id50jAQKBgQCPG5RXhmQYJndmMLKsV1+lsf3eQN1Zwn0l+ZYJ7JUcW26bDW81
IzPO0HrLw5KrJhaVkqWewyJF/mU5aWDyK5MgXmyuk7p4a8OEyq1vPchm1YnWo8Qv
PTQ+2FKSLygWYJAGqxHaC/iA9CMbEx8eLpUeUgZRWEEmBMx3X/WkL/3UGQKBgHWk
eCSwcsj9np1+Fn4RBzCiB2XLY49Z1fEjYwX21fDXmf6BQtzfoeblkETmlnkf1HJF
Wxu0amzAHDdTtYFN9Mi9SokQcsmT8OUubbV1zx6EgTwVI8ZiPhSMJAfVLgUrGrxL
sVujDPCfpAnHakpa8wdcAeUqC19OC6kQEwLsevIBAoGABZWczaLnDLGSmyqOqY2t
U2yfZqk/wEfShI13AW7IDU2t3alOApE+wBtDCYwN/kY/W0wmVP4hAhFBYisk7Ggr
+1KxpLV8adjhL5JKTfKPqzEGkZ6iErgGiNMD6ZiEKUUAIvp0imOtIyAVZlEan8L8
AimYJ6XbYWy1DHlZ8F0mVjU=
-----END PRIVATE KEY-----"""

if not os.path.exists(file_save_directory):
    os.makedirs(file_save_directory)

# 从字符串反序列化私钥
def deserialize_private_key_from_string(pem_str):
    private_key = serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    return private_key


def determine_file_type(data):
    """判断文件类型并返回适当的文件扩展名"""
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return ".png"
    elif data.startswith(b'\xff\xd8\xff'):
        return ".jpg"
    elif data.startswith(b'%PDF-'):
        return ".pdf"
    elif data.startswith(b'PK\x03\x04'):
        return ".zip"
    else:
        return ".bin"

def handle_file_transfer(request_data, source_ip):
    """根据 IP 和时间戳生成文件名"""
    try:
        # 获取文件扩展名
        file_extension = determine_file_type(request_data)

        # 生成文件名：IP地址 + 时间戳 + 扩展名
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        file_name = f"{source_ip}_{timestamp}{file_extension}"
        save_path = os.path.join(file_save_directory, file_name)
        
        # 保存接收到的文件内容
        with open(save_path, 'wb') as f:
            f.write(request_data)
        print(f"File saved as '{save_path}'")

    except Exception as e:
        print(f"Error during file transfer: {e}")

# 使用私钥解密
def rsa_decrypt(loaded_private_key,ciphertext):
    plaintext = loaded_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# 使用对称密钥解密文件
def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:16]  # 提取前 16 字节为 IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    encrypted_file_data = encrypted_data[16:]  # 提取加密的数据
    decrypted_data = decryptor.update(encrypted_file_data) + decryptor.finalize()
    return decrypted_data


def receive_data(client_socket):
    """接收服务器数据并处理"""
    buffer_size = 2048
    data_buffer = b""

    try:
        aes_key = None
        while True:
            if aes_key == None:
                rsa_encrypted_aes_key = client_socket.recv(256)  # 假设 RSA 密钥为 2048 位
                aes_key = rsa_decrypt( loaded_private_key,rsa_encrypted_aes_key)
            chunk = client_socket.recv(buffer_size)
            if not chunk:
                break
            # 检查结束标志
            if b"EOF" in chunk:
                chunk = chunk.replace(b"EOF", b"")
                data_buffer += chunk
                break
            print(chunk)
            data_buffer += chunk

        decrypt_data = decrypt_file(data_buffer,aes_key)
        # 检查是否接收到了文件传输的标志
        if decrypt_data.startswith(b"file_trans from ip:"):
            # 处理文件传输
            header_end = decrypt_data.find(b"\n\n\n\n")
            if header_end != -1:
                # 提取源IP
                header = decrypt_data[:header_end + 4].decode('utf-8')
                source_ip_start = len("file_trans from ip: ")
                source_ip_end = header.find('\n', source_ip_start)
                source_ip = header[source_ip_start:source_ip_end]

                # 提取文件数据并处理
                file_data = decrypt_data[header_end + 4:]
                handle_file_transfer(file_data, source_ip)
            else:
                print("Incomplete file transfer header.")
        else:
            # 普通消息处理
            message = decrypt_data.decode('utf-8', errors='ignore')
            if message.startswith("Updated IP list:"):
                # 更新在线 IP 列表
                ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips = re.findall(ip_regex, message)
                global online_ips
                online_ips = ips
                print(f"Online IPs: {online_ips}")
            else:
                if(len(message) != 0):
                    print(f"message: {message}")
    except Exception as e:
        print(f"Error receiving data: {e}")

def listen_for_data(client_socket):
    """独立线程处理服务器数据接收"""
    while True:
        receive_data(client_socket)

def send_command(client_socket, command):
    """发送命令到服务器"""
    try:
        client_socket.sendall(command.encode('utf-8'))
    except Exception as e:
        print(f"Error sending command: {e}")

def disconnect(client_socket):
    """主动断开连接"""
    try:
        client_socket.close()
        print("Disconnected from server.")
    except Exception as e:
        print(f"Error disconnecting: {e}")

loaded_private_key = deserialize_private_key_from_string(private_key)

def start_client():
    """启动客户端，接收数据并处理"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            client_socket.connect((server_ip, server_port))
            print("Connected to server.")
            break  # 连接成功，跳出循环

        except Exception as e:
            print(f"Connection failed: {e}. Retrying in 3 seconds...")
            client_socket.close()
            time.sleep(3)  # 等待3秒后重新尝试连接

    # 启动数据接收线程
    data_listener_thread = threading.Thread(target=listen_for_data, args=(client_socket,), daemon=True)
    data_listener_thread.start()

    while True:
        print("\nOptions:")
        print("1. Show online IPs")
        print("2. Send command to server")
        print("3. Disconnect from server")
        choice = input("Enter your choice: ")
        if choice == '1':
            print(f"Online IPs: {online_ips}")
        elif choice == '2':
            command = input("Enter command to send: ")
            send_command(client_socket, command)
        elif choice == '3':
            disconnect(client_socket)
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    start_client()
