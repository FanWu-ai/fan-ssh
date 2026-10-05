# fan-ssh

用 Python 为已有 SSH 登录提供经过身份验证的设备间直连通道。以普通用户运行，支持 TCP/TLS，以及显式启用的原生 UDP ICE/DTLS/SCTP；保留系统 OpenSSH 的用户认证和主机密钥校验。协调器只交换受限的控制信息，不转发 SSH 业务流量。

适合在自己管理或已获授权的设备之间尝试直连，也支持单独配置的**显式本地电脑桥接**。它不会自动修改防火墙、路由、SSH 认证或安装后台服务，不能保证穿透所有 NAT 或被封锁的 UDP 网络。

## 日常使用

先完成[首次配置](#首次配置)，并保持协调器、接收节点运行。之后在发起端使用已保存的连接：

```sh
fan-ssh profile list
fan-ssh doctor remote
fan-ssh connect remote
```

`doctor` 只检查本地配置，不探测网络，也不代表直连或 SSH 登录成功。以上短命令需在已激活的虚拟环境中执行；未激活时可使用虚拟环境 Python 加 `-m fan_ssh`，例如 Windows 的 `.\.venv\Scripts\python.exe -m fan_ssh connect remote`。

## 当前验证与限制

截至 2026-10-05，**本地 Windows 工作站 ↔ 远程局域网设备 D 的 Python 原生连接已验证**：实际 `python -m fan_ssh ssh` 完成 3 次严格主机密钥校验的 SSH 登录，8 MiB 上传和精确 8 MiB 往返数据均通过 SHA-256 校验。两端物理路由已核实，未启动 FRP 进程，业务数据未走 Tailscale 或云端中继。[Python 实测证据](test-results/python-ssh-remote-lan-d-20261005.json)

新增的 `profile` / `connect` / `doctor` 本次仅完成云端 Linux 本地回归和安装检查，尚未在 Windows 或真实公网环境重新验证这些入口。上面的真实连接证据属于原 `ssh` 入口。

**仍未验证：**远程局域网设备 A、C 的可用 Python 原生连接，最初要求的 A ↔ B 直连，以及 A ↔ 本地工作站 ↔ B 的完整桥接拓扑。一个网络组合或桥接中的一段成功，不能代表其他组合或完整拓扑成功。Windows 单独的 asyncio-debug 压力测试仍有间歇性流错误，未宣称修复。临时测试授权不等于永久部署授权。[完整验证记录](VALIDATION.md)

## 开始前：三个角色与前提

一次连接需要：

1. **协调器 `control`**：双方可访问的控制端点，签发有时限的定向授权；启用 UDP 时可同时提供显式配置的 STUN 观察端口。
2. **接收端 `b`**：运行 `node`，将一个获批服务映射到已有的本机 loopback SSH 服务，例如 `127.0.0.1:22`。
3. **发起端 `a`**：运行 `connect` 或完整 `ssh` 入口，用本机已有 OpenSSH 配置登录接收端。

这里的 `a`、`b` 是示例角色 ID，与上面的历史测试设备标签 A–D 无对应关系。协调器身份不能作为业务节点；同一台机器若兼任节点，必须使用另一份独立身份和数据端口。

请先准备：

- 各角色使用 Python 3.11+ 和当前版本代码。已实测 Python 3.12.3/3.12.10；最低版本 Python 3.11 和 macOS 运行时尚未完成验证。
- 发起端有可用的系统 OpenSSH 客户端；接收端已有 SSH 服务。
- 已有 SSH 别名、经过核实的 `known_hosts` 记录，以及可非交互使用的 SSH 凭据。入口强制 `BatchMode=yes`，不会自动配置免密登录或复制密钥。
- 经设备所有者批准的身份、策略、物理接口地址和端口；协调器及观察端口已有可用路径，或相关网络变更已另行授权。
- 接收端与协调器在使用期间保持运行。以下都是前台进程，不是服务部署步骤。

**地址说明：**文中的 `192.0.2.*`、`198.51.100.*` 是文档专用地址，不能原样用于真实连接。请替换为已批准的实际地址。`--listen` 绑定本机已有的地址；策略中的协调器地址和 `--stun` 应是双方可达的地址。存在公网映射时，这两种地址可能不同。

## 首次配置

### 1. 下载、创建虚拟环境并安装

在需要运行 fan-ssh 的每台机器上安装。Linux/macOS shell：

```sh
git clone https://github.com/FanWu-ai/fan-ssh.git
cd fan-ssh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[udp]'
```

Windows PowerShell：

```powershell
git clone https://github.com/FanWu-ai/fan-ssh.git
Set-Location fan-ssh
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[udp]'
```

Windows 后续命令中的 `python` 可直接替换为 `.\.venv\Scripts\python.exe`，无需更改 PowerShell 执行策略。下面的多行命令采用 POSIX shell 的 `\` 续行；在 PowerShell 中请合并为一行，或使用 PowerShell 续行语法。

只用 TCP 时可安装 `python -m pip install -e .`，并省略后文的 UDP/STUN 参数。基础依赖是 `cryptography>=42,<51`；UDP 额外依赖固定为 `aiortc==1.15.0` 和 `aioice==0.10.2`。UDP 适配器使用库的私有 API，会拒绝不兼容版本。程序运行时不会自动下载依赖。

### 2. 在各自设备上创建身份

先在每台设备上创建父目录：

```sh
mkdir -p .fan-ssh
```

PowerShell 对应命令为 `New-Item -ItemType Directory -Force .fan-ssh | Out-Null`。

**Windows 身份目录必须位于支持 ACL 的文件系统**，例如用户目录下的 NTFS。若源码目录在 exFAT/FAT 上，请将身份放到 `$env:LOCALAPPDATA\fan-ssh` 下，并相应替换后续所有 `--directory` / `--identity` 路径。新建身份会在写入私钥前检查 ACL；不要通过放宽私钥权限绕过检查。

仅在协调器执行：

```sh
python -m fan_ssh identity-init --id control --directory .fan-ssh/control --public control.public.json
```

仅在发起端执行：

```sh
python -m fan_ssh identity-init --id a --directory .fan-ssh/a --public a.public.json
```

仅在接收端执行：

```sh
python -m fan_ssh identity-init --id b --directory .fan-ssh/b --public b.public.json
```

身份目录和公有记录文件必须是新路径，命令拒绝覆盖。**各设备的私钥目录留在本机**；只通过已有可信渠道交换 `*.public.json`，并与设备所有者核对命令输出的 SHA-256 指纹。需要重新导出公有记录时使用 `identity-export`，无需重新生成身份。

### 3. 批准设备与定向服务策略

设备所有者核对身份、地址和访问范围后，将三份公有记录收集到批准策略的机器上，执行：

```sh
python -m fan_ssh policy-build --account example-account --revision 1 \
  --coordinator control --coordinator-address 198.51.100.10:22090 \
  --device control.public.json --device a.public.json --device b.public.json \
  --candidate a=192.0.2.10:22022 --candidate b=192.0.2.20:22022 \
  --allow a:b:ssh --output network.policy.json
```

将同一份已批准的 `network.policy.json` 分发到三个角色。此示例只允许 `a` 访问 `b` 的 `ssh` 服务；如需反方向发起 SSH，须另行批准 `b:a:ssh`，并在相应接收端运行节点。反向 TCP 建链机制本身不会改变服务授权方向。

`policy-build` 负责校验和生成策略文件，**执行成功不代表替代了所有者审批**。它只创建新文件。设备、账户、服务名使用 ASCII 字母、数字、下划线或连字符。候选端点必须为数值单播 IP 和 1024–65535 端口；每设备最多 8 个候选，策略最多 64 个身份和 4096 条定向服务授权。

### 4. 启动协调器

在协调器的独立终端执行并保持运行：

```sh
python -m fan_ssh coordinator --identity .fan-ssh/control --policy network.policy.json \
  --listen 198.51.100.10:22090 \
  --stun-listen 198.51.100.10:22092 \
  --stun-alternate-listen 198.51.100.10:22093
```

这里使用一个 TCP 控制端口和两个 UDP 观察端口，每个都需要已有或另行批准的可达路径。第二个观察端口是可选项；如不使用，请同时从两端命令中去掉 `--stun-alternate`。STUN 仅观察地址，不转发业务数据，也不提供 TURN。

### 5. 启动接收节点

在接收端 `b` 的独立终端执行并保持运行：

```sh
python -m fan_ssh node --identity .fan-ssh/b --policy network.policy.json \
  --listen 192.0.2.20:22022 --service ssh=127.0.0.1:22 \
  --udp-native 192.0.2.20 \
  --stun 198.51.100.10:22092 --stun-alternate 198.51.100.10:22093
```

`--service` 只接受操作方固定的数值 loopback 目标，不允许调用者任意指定目标。请确认已有 SSH 服务确实监听该 loopback 地址/端口。

`--udp-native` 必须是**本机物理接口 IP**，且已列入本设备获批候选地址。它不是 SSH 别名、覆盖网络地址或任意公网映射地址。UDP 会在该 IP 上绑定临时端口；策略示例中的 `22022` 是 TCP 候选端口，不是固定 UDP 会话端口。

### 6. 保存发起端连接，之后使用短命令

在发起端 `a` 保存一次连接参数：

```sh
python -m fan_ssh profile add remote \
  --identity .fan-ssh/a --policy network.policy.json \
  --peer b --ssh-host existing-b-alias \
  --udp-native 192.0.2.10 \
  --stun 198.51.100.10:22092 --stun-alternate 198.51.100.10:22093
```

将 `existing-b-alias` 替换为已有且主机密钥已核实的 SSH 别名。源端也必须提供自己的物理 IP 和 STUN 参数；只在接收端启用 UDP 不会启用源端 UDP。

然后检查并连接：

```sh
python -m fan_ssh doctor remote
python -m fan_ssh connect remote
# 目标为 Linux 时，也可执行远程命令：
python -m fan_ssh connect remote -- uname -a
```

查看已保存的连接：

```sh
python -m fan_ssh profile list
python -m fan_ssh profile show remote
```

每个名称对应一个本机 JSON 文件。`profile add` 只校验选项并保存引用；它不会创建身份、复制私钥、配置免密或授予设备权限。相对的 identity/policy 路径会转成绝对路径保存，之后可从其他工作目录调用。

默认保存目录：

- Linux：`${XDG_CONFIG_HOME:-~/.config}/fan-ssh/profiles`
- Windows：`%LOCALAPPDATA%\fan-ssh\profiles`
- macOS：`~/Library/Application Support/fan-ssh/profiles`（运行时仍未验证）

同名配置拒绝覆盖。需要修改时，先用 `profile show remote` 查看文件位置，再编辑该文件并运行 `doctor`，或另取连接名称。配置含本机路径、SSH 别名和网络地址，请勿直接发布。

成功加载 profile 后，`doctor` 用 JSON 列出检查结果；退出码 0 表示本地检查通过，1 表示检查失败。检查内容包括身份及私有权限、策略/定向授权、物理或反向候选是否获批、OpenSSH 程序是否存在，以及启用 UDP 时的固定依赖版本。它**不检查**网络/NAT、协调器或接收节点是否运行、SSH 有效配置、用户凭据和 `known_hosts`；也不会执行 `ssh -G`。

别名用于已有用户凭据和主机密钥查找；数据连接由 Python ProxyCommand 提供。连接时，`connect` / `ssh` 入口会先检查 `ssh -G` 的有效配置，确认实际启用的是该 Python 代理；检查失败会停止，不会悄悄退回别名原来的管理连接。可在 `profile add` 或完整 `ssh` 命令中用 `--ssh-user` / `--ssh-port` 指定已有登录用户和原 SSH 端口。

入口强制严格主机密钥校验、关闭 agent 转发和主机密钥自动更新，并清除 SSH 配置中的额外转发。设备获批不等于获得操作系统登录权限，最终仍由系统 OpenSSH 认证用户。

## 自动选择与直连边界

`connect` 使用已保存的传输配置；远程 `ssh` / `proxy` / `forward` 和新建 profile 默认 `--transport auto`，按以下顺序尝试：

1. 正向 TCP，最多 12 秒。
2. 配置了反向监听时的反向 TCP，最多 12 秒。
3. 显式启用 UDP 后的普通 ICE，最多 28 秒。
4. 显式启用 UDP 后的 IPv4 UDP 端口预测，最多 50 秒，包含一次全新连接重试。

每种方式使用新的授权和连接状态。普通连通性失败才会进入下一种方式；身份、证书、策略、授权或权限错误会终止连接。stderr 会记录尝试和选中的路径。全部失败返回 `NO_DIRECT_PATH`，不会自动选择业务中继。限制较多的网络初次连接可能需要几十秒；SSH 入口为初始连接保留 120 秒超时。

下面的连接选项用于 `profile add` 或完整 `ssh` / `proxy` / `forward` 命令。`connect` 的名称后只接受远程命令，不接受临时连接选项。

- `--transport tcp`：只用 TCP。
- `--transport udp`：只用 UDP，默认普通 ICE。
- `--transport udp --udp-strategy predict`：明确使用 IPv4 端口预测，适用于已经验证该方式可行的网络组合。
- `--reverse-listen IP:PORT --reverse-candidate IP:PORT`：使用获批且实际可达的源端监听地址尝试反向 TCP；通告地址必须属于源端获批候选。

UDP 必须同时提供 `--udp-native` 和 `--stun`，并安装 UDP extra；示例使用显式批准的数值 IPv4 STUN 观察端点。程序不会自动收集所有网卡、使用默认外部 STUN、添加 TURN 或扫描公共端口。接收节点默认允许启用的 ICE/预测策略；`--no-reverse` 会关闭**全部反向/UDP offer 轮询**，也会阻止这种 UDP 接入。

原生 UDP 只交换 host/server-reflexive 候选，核对获批 IP、控制连接观察到的出口 IP 及精确 DTLS 证书指纹。多出口或出口变化可能被保守拒绝。预测仅对同意参与的对端映射附近最多 21 个高端口进行带认证的低 TTL 预热，再执行 ICE 和 DTLS。STUN 有响应不代表对端可达，同一观察 IP 的两个端口也不能证明跨 IP 映射独立性。

## 排查连接

- **`PROFILE_NOT_FOUND` / `PROFILE_ALREADY_EXISTS`：**用 `profile list` 确认名称和 profile 目录；新增同名配置不会覆盖旧文件。
- **先区分安装、身份、控制连接和数据路径。**三个角色均需使用当前版本；旧版单操作协调器不支持新版本的信令连接复用。
- **`UDP_EXTRA_REQUIRED` / `UDP_ADAPTER_VERSION_UNSUPPORTED`：**检查正在使用的虚拟环境，并按固定版本安装 `.[udp]`。
- **`NATIVE_ADDRESS_NOT_APPROVED`：**核对本机物理 IP 与策略候选；不要为了绕过检查随意扩大批准范围。
- **`ACL_DENIED` / 证书或指纹错误：**核对身份、公有记录、账户、策略版本、定向服务名和证书有效期。服务名须在策略、`node` 和发起命令中一致。
- **`SSH_PYTHON_PROXY_NOT_ACTIVE`：**检查已有 SSH 配置及 `ssh -G` 的有效输出，确认 Python ProxyCommand 生效；不要改成管理网络直连后仍当作 fan-ssh 成功。
- **SSH 用户认证或主机密钥错误：**按原 SSH 管理流程核实凭据/主机密钥。不要关闭严格校验，也不要把服务授权当成用户登录授权。
- **`NO_DIRECT_PATH` / 超时：**核对两端进程、物理绑定、数值 STUN 端点、已有网络路径及 offer 轮询。难穿透的 NAT 或 UDP 封锁可能确实没有可用直连路径。
- **Windows 身份权限错误：**使用用户私有的 ACL/NTFS 目录。源码可位于别处，私钥目录不可因此放宽权限。
- **Windows UDP 调试模式失败：**产品使用非 debug 的 selector 事件循环；Python 3.12 proactor 下曾出现持续双向 DTLS 停滞。`FAN_SSH_UDP_DEBUG_TESTS=1` 是另行保留的压力复现，不属于已修复路径。

只检查正向 TCP 的身份验证通道，可以执行：

```sh
python -m fan_ssh diagnose --identity .fan-ssh/a --policy network.policy.json \
  --peer b
```

`diagnose` 不测试 UDP，不连接接收端 sshd，不发送 SSH 数据；`AUTHENTICATED_DIRECT_TLS` 不能代替完整 SSH 登录和传输校验。

## 进阶用法

### 使用其他 profile 目录

各 profile 命令、`doctor` 和 `connect` 支持 `--profiles-dir PATH`。`connect` 的这个选项必须放在连接名称之前，避免被当作远程命令：

```sh
fan-ssh connect --profiles-dir /path/to/profiles remote -- uname -a
```

该目录需已保存相应配置；所有相关命令使用同一目录。没有指定时使用前述系统默认目录。

### 不保存连接参数，直接使用 `ssh` 入口

原来的完整命令仍可使用，参数不会写入 profile：

```sh
python -m fan_ssh ssh --identity .fan-ssh/a --policy network.policy.json \
  --peer b --ssh-host existing-b-alias \
  --udp-native 192.0.2.10 \
  --stun 198.51.100.10:22092 --stun-alternate 198.51.100.10:22093
```

与 `connect` 一样，可在 `--` 后传入远程命令。

### 手动 ProxyCommand 或本地转发

通常优先使用上面的 `connect` / `ssh` 入口。已有高级 OpenSSH 配置仍可显式使用原始代理；下面是 TCP 路径示例：

```sh
ssh -o 'ProxyCommand=python -m fan_ssh proxy --identity .fan-ssh/a --policy network.policy.json --peer b --transport tcp' \
  -o HostKeyAlias=existing-b-alias -o StrictHostKeyChecking=yes \
  -o BatchMode=yes -o ForwardAgent=no -o UpdateHostKeys=no -o ClearAllForwardings=yes existing-b-alias
```

实际配置应使用虚拟环境 Python 的绝对路径和正确的 shell 引号，并自行核对有效 SSH 配置。原始 `proxy` 的 stdout 只输出 SSH 字节，诊断信息写到 stderr。

也可在源端启动本地转发，再从另一个终端连接：

```sh
python -m fan_ssh forward --identity .fan-ssh/a --policy network.policy.json \
  --peer b --transport tcp --listen 127.0.0.1:2222
ssh -p 2222 -o HostName=127.0.0.1 -o HostKeyAlias=existing-b-alias \
  -o ProxyCommand=none -o ProxyJump=none -o StrictHostKeyChecking=yes \
  -o BatchMode=yes -o ForwardAgent=no -o UpdateHostKeys=no -o ClearAllForwardings=yes existing-b-alias
```

本地转发入口不认证本机调用者；SSH 仍负责最终用户认证。使用非标准原 SSH 端口或自定义 `HostKeyAlias` 时，应按已有配置保留准确的主机密钥查找名称，优先使用封装入口的 `--ssh-port`。

### 显式本地电脑桥接（`home-bridge`）

仅用于已经单独批准的拓扑。源端到本地电脑、本地电脑到最终设备都必须有独立可用的直连路径；直连失败不会自动启用桥接。协调器继续只承担控制角色。

在作为桥接节点的本地电脑上创建第四份独立身份：

```sh
python -m fan_ssh identity-init --id bridge --directory .fan-ssh/bridge --public bridge.public.json
```

按前述流程核对并交换公有记录后，建立**单独批准的桥接策略**：

```sh
python -m fan_ssh policy-build --account example-account --revision 1 \
  --coordinator control --coordinator-address 198.51.100.10:22090 \
  --device control.public.json --device a.public.json --device b.public.json --device bridge.public.json \
  --candidate a=192.0.2.10:22022 --candidate b=192.0.2.20:22022 --candidate bridge=192.0.2.30:22022 \
  --allow a:bridge:remote-ssh --allow bridge:b:ssh --output bridge.policy.json
```

该示例是独立配置：将同一份 `bridge.policy.json` 分发到所有角色，并让协调器使用它重新启动。若更新已有部署，必须使用更高的 revision，不能用示例中的 revision 1 覆盖正在运行的策略。

以下展示各段 TCP 已可达时的启动方式：

```sh
# 最终接收端 b：
python -m fan_ssh node --identity .fan-ssh/b --policy bridge.policy.json \
  --listen 192.0.2.20:22022 --service ssh=127.0.0.1:22
# 本地电脑 bridge，固定转到 b/ssh：
python -m fan_ssh home-bridge --identity .fan-ssh/bridge --policy bridge.policy.json \
  --listen 192.0.2.30:22022 --bridge-service remote-ssh --peer b --transport tcp
# 源端 a，仍使用最终设备 b 的已有 SSH 身份与主机密钥：
python -m fan_ssh ssh --identity .fan-ssh/a --policy bridge.policy.json \
  --peer bridge --service remote-ssh --ssh-host existing-b-alias --transport tcp
```

两条授权分别控制进入桥接服务和访问最终服务，调用者不能更改最终目标。各段可按需配置已批准的原生 UDP 或反向 TCP；`home-bridge` 的 `--transport` 控制出站段，`--udp-native` 与 `--stun` 成对配置后同时启用入站/出站 UDP。出站反向 TCP 监听需要另一个获批端口。

桥接通过匿名本地 socket pair 转发不透明的 SSH 字节，不新增未认证的 loopback 转发端口。SSH 加密与用户认证仍在源端和最终设备之间；桥接电脑是影响可用性、可观察流量元数据的信任参与方。`DIRECT_SERVICE_READY` 只代表源端获准进入桥接服务，`HOME_BRIDGE_UPSTREAM_READY` 才表示出站段独立获准；完整验收仍需最终严格 SSH 登录、数据完整性以及两段原生路由证据。

### 策略更新与安全边界

- 原子替换策略文件时必须提高 revision。协调器/节点约每秒检查一次；无效更新或回滚保留上一份有效快照。节点策略变更会保守地关闭现有会话。
- 客户端在启动时加载策略，变更后需重启。桥接策略变更会关闭会话，且桥接进程重启后才能接收新连接；协调器证书指纹轮换也需要重新批准并重启。
- 签名授权绑定账户、版本、双方指纹、定向服务、传输方式、会话、过期时间和序号。初始租约 30 秒，接收端在租约中段续期；续期失败、撤销或过期会关闭流。会话上限 24 小时，保留 32 会话容量限制，协调器需持续可用。
- 自签 P-256 叶证书经人工批准后作为精确可信身份。TCP 使用 TLS 1.3、证书校验与 SHA-256 指纹固定；UDP 使用相互固定指纹的 DTLS。
- 私钥以未加密形式保存，依靠用户私有目录及文件权限保护；这不是硬件密钥托管，也不能防御已被攻陷的本机用户或管理员。Windows 的 SYSTEM/Administrators 属于允许的特权主体。
- STUN 观察器只响应已在认证控制连接中出现过的源 IP，限制为 IPv4 Binding 请求、20–256 字节、每 IP 每分钟最多 60 次。临时观察器和网络授权不能自动沿用为永久部署。

## 本地测试与研究资料

[已归档的 0.3 产品回归记录](test-results/python-product-regressions-20261005.json)中，普通用户 Linux 主机 90 项测试全部通过，另有 26 项 TCP 诊断和 demo 通过；Windows 产品默认事件循环下为 87 项通过、3 项 Linux 专用测试跳过。此记录不覆盖后续新增功能，也不代表独立 debug 压力测试已修复。

在安装了 UDP extra 的环境中运行：

```sh
python -m fan_ssh demo
python -m unittest discover -s tests -v
python -m unittest discover -s experiments/tcp-simopen -v
```

`demo` 和不带 `--peer` 的 `proxy/forward --target LOOPBACK:PORT` 只是生成临时身份的 loopback 测试，数据时限 30 秒，不会注册或连接远端设备。根测试发现不会自动包含 `experiments/`；Linux socket 和阻塞 stdio 测试应在真实 Linux 主机运行，跳过不等于通过。

研究工具与快速开始分开使用，须先获得对应主机、地址、端口和操作范围的明确授权：

- [scripts/README.md](scripts/README.md)：离线 Linux 回归、私有 inventory、受限真实网络测试及清理方法。`campaign.py` 退出 0 只代表编排/清理完成，应逐项检查试验结果。
- [TCP 实验](experiments/tcp-simopen/README.md)：同步建链等诊断研究，不是已通过验收的自动生产回退。
- [FRP 物理接口绑定对照](experiments/frp-device-binding/README.md)及[工作站 ↔ 远程局域网设备 D 的原生参考结果](test-results/frp-workstation-remote-lan-d-native-20261005.json)：历史对照，不是 Python 运行依赖或实现验收替代品。
- `native_udp_probe.py` / `native_udp_birthday.py` / `native_tcp_ttl_probe.py`：受限控制探测；TCP 建连、STUN 响应或探测包成功不能代替 SSH 登录。
- `dual_stun_observer.py` / `tcp_stun_observer.py` / `stun_probe.py`：显式获批端点的地址观察工具。
- `easytier_peer_check.py`：核查参考实现实际选中的原生直连；两跳路由或未被使用的连接不算成功。
- `upnp_inspect.py`：只读网关与外部地址查询，不添加端口映射。

历史诊断曾在远程局域网设备 A 观察到 STUN 域名解析为 `198.18.*` 基准测试地址，且不同观察路径的出口不一致。这与 Fake-IP DNS 行为相符，但未确定负责该行为的网络组件。改用数值观察端点偶尔获得响应，也未证明设备间路径成立。Python 传输仍只使用明确批准的数值观察端点和原生 IP。

私有 inventory、地址、身份资料、凭据及原始日志应保留在忽略的私有目录中；提交前仍需自行检查，不要将真实环境信息写入公开证据。

进一步阅读：

- [ARCHITECTURE.md](ARCHITECTURE.md)：协议、身份、授权和传输设计。
- [VALIDATION.md](VALIDATION.md)：实际验证、历史失败和待完成的验收。
- [HANDOFF.md](HANDOFF.md)：实现背景、研究进展和后续工作。

目前未宣称完成普适 NAT 穿透、休眠/漫游恢复、生产部署、包仓库发布或安全审计；仓库也不代表已选择开源许可证。没有获准且可用的原生路径时，应如实报告失败，不能把覆盖网络或云端业务中继记作直连成功。
