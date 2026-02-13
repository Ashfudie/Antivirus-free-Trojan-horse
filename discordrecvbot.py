# import discord
# import base64
# from PIL import Image
# from io import BytesIO

# intents = discord.Intents.default()
# intents.message_content = True

# client = discord.Client(intents=intents)

# def bin_to_text(bin_data):
#     """将二进制字符串转换为文本"""
#     text = ''.join([chr(int(bin_data[i:i+8], 2)) for i in range(0, len(bin_data), 8)])
#     return text

# def extract_text_from_image(image_bytes):
#     """从图片中提取隐藏的文本"""
#     img = Image.open(BytesIO(image_bytes))
#     bin_data = ''
#     pixels = img.load()
#     width, height = img.size

#     for i in range(height):
#         for j in range(width):
#             pixel = list(pixels[j, i])
#             for n in range(3):  # 对 R, G, B 三个通道进行操作
#                 bin_data += format(pixel[n], '08b')[-1]  # 获取最低有效位

#     all_bytes = [bin_data[i:i+8] for i in range(0, len(bin_data), 8)]
#     hidden_text = ""
#     for byte in all_bytes:
#         if byte == '11111110':  # 结束标志符
#             break
#         hidden_text += chr(int(byte, 2))

#     return hidden_text

# def decrypt(encoded_string):
#     """解密base64编码的字符串"""
#     # 检查字符串长度是否是4的倍数，不是的话添加'='作为填充
#     missing_padding = len(encoded_string) % 4
#     if missing_padding:
#         encoded_string += '=' * (4 - missing_padding)
    
#     base64_bytes = encoded_string.encode('utf-8')
#     decoded_bytes = base64.b64decode(base64_bytes)
#     return decoded_bytes.decode('utf-8')


# @client.event
# async def on_message(message):
#     if message.author == client.user:
#         return

#     # 检查是否是图片消息
#     if message.attachments:
#         for attachment in message.attachments:
#             if attachment.filename.startswith('image_chunk'):
#                 image_bytes = await attachment.read()
#                 extracted_text = extract_text_from_image(image_bytes)
#                 chunk_number, chunk = extracted_text.split(':', 1)
#                 chunk = decrypt(chunk)
#                 print(f"Received chunk {chunk_number}: {chunk}")
    
#     # 检查是否是文本消息
#     elif message.content.startswith('Here is chunk'):
#         chunk_with_number = message.content.split('`')[1]
#         chunk_number, chunk = chunk_with_number.split(':', 1)
#         chunk = decrypt(chunk)
#         print(f"Received chunk {chunk_number}: {chunk}")

# client.run('client-secret')
# here is your client-secret
import discord
import base64
from PIL import Image
from io import BytesIO
count = 0
intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)

def bin_to_text(bin_data):
    """将二进制字符串转换为文本"""
    text = ''.join([chr(int(bin_data[i:i+8], 2)) for i in range(0, len(bin_data), 8)])
    return text

def extract_text_from_image(image_bytes):
    """从图片中提取隐藏的文本"""
    img = Image.open(BytesIO(image_bytes))
    bin_data = ''
    pixels = img.load()
    width, height = img.size

    for i in range(height):
        for j in range(width):
            pixel = list(pixels[j, i])
            for n in range(3):  # 对 R, G, B 三个通道进行操作
                bin_data += format(pixel[n], '08b')[-1]  # 获取最低有效位

    all_bytes = [bin_data[i:i+8] for i in range(0, len(bin_data), 8)]
    hidden_text = ""
    
    # 使用两个字节作为结束标志符，确保正确处理16位的结束符
    for i in range(0, len(all_bytes), 1):
        byte_pair = all_bytes[i:i+2]
        if len(byte_pair) == 2 and ''.join(byte_pair) == '1111111111111110':  # 匹配16位结束符
            break
        hidden_text += chr(int(byte_pair[0], 2))

    return hidden_text

def decrypt(encoded_string):
    """解密base64编码的字符串"""
    # 检查字符串长度是否是4的倍数，不是的话添加'='作为填充
    missing_padding = len(encoded_string) % 4
    if missing_padding:
        encoded_string += '=' * (4 - missing_padding)
    
    base64_bytes = encoded_string.encode('utf-8')
    decoded_bytes = base64.b64decode(base64_bytes)
    return decoded_bytes.decode('utf-8')

received_chunks = {}  # 用于存储接收到的Base64块，使用字典按编号存储
total_chunks = None  # 用于存储总的块数

@client.event
async def on_message(message):
    global count, received_chunks, total_chunks
    if message.author == client.user:
        return

    # 处理附件（图片或文件）
    if message.attachments:
        for attachment in message.attachments:
            # 处理图像消息
            if attachment.filename.startswith('image_chunk'):
                image_bytes = await attachment.read()
                extracted_text = extract_text_from_image(image_bytes)

                if ':' in extracted_text:
                    chunk_number, chunk = extracted_text.split(':', 1)
                    print(f"Received image chunk {chunk_number}: {chunk}")  # 调试信息
                    count += 1

                    received_chunks[int(chunk_number)] = chunk  # 存储块到字典
                    if chunk == "EOF":
                        total_chunks = int(chunk_number)
                    if total_chunks == count:
                        check_and_decode_message()
                        count = 0

            # 处理文件消息
            elif attachment.filename.startswith('chunk_'):
                file_bytes = await attachment.read()
                file_content = file_bytes.decode('utf-8')

                if ':' in file_content:
                    chunk_number, chunk = file_content.split(':', 1)
                    print(f"Received file chunk {chunk_number}: {chunk}")  # 调试信息
                    count += 1
                    received_chunks[int(chunk_number)] = chunk  # 存储块到字典
                    if chunk == "EOF":
                        total_chunks = int(chunk_number)
                    if total_chunks == count:
                        check_and_decode_message()
                        count = 0

    # 处理文本消息
    elif message.content.startswith('Here is chunk'):
        chunk_with_number = message.content.split('`')[1]
        if ':' in chunk_with_number:
            chunk_number, chunk = chunk_with_number.split(':', 1)
            print(f"Received text chunk {chunk_number}: {chunk}")  # 调试信息
            count += 1
            received_chunks[int(chunk_number)] = chunk  # 存储块到字典
            if chunk == "EOF":
                total_chunks = int(chunk_number)
            if total_chunks == count:
                check_and_decode_message()
                count = 0

def check_and_decode_message():
    """检查是否所有块都已接收并解码消息"""
    global received_chunks, total_chunks
    if total_chunks is not None and len(received_chunks) == total_chunks:
        # 拼接所有接收到的Base64块，去除最后的EOF
        try:
            full_base64_data = ''.join(received_chunks[i] for i in range(1, total_chunks))
            full_text = decrypt(full_base64_data)  # 解码完整的Base64数据
            print(f"Received full message: {full_text}")
        except Exception as e:
            print(f"Error during decoding: {e}")
        finally:
            received_chunks.clear()  # 清空块缓存
            total_chunks = None

client.run('your-client-secret')
