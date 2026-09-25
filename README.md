# 液氙标定档案 · 崩溃安全的主密钥轮换

密封液氙标定读数（**AES-256-GCM** 信封加密），并支持主密钥轮换在**任意一条记录重包裹后进程崩溃**时安全恢复：已归档读数始终可读，半轮换密钥永不被误用。

## 安全模型

- 每条标定记录生成**独立数据密钥 DEK**；记录明文以 AES-256-GCM 加密，nonce 随机、AAD 绑定 `record id + 内容摘要`。
- DEK 由**当前主密钥**以 AES-256-GCM 包裹，包裹 AAD 绑定 `record id + 主密钥版本 kid`，包裹不能在记录或主密钥版本间挪用。
- 主密钥保存在 SQLite（WAL + `synchronous=FULL`），状态为 `active / staged / retired`。
- 轮换逐条进行，**每条重包裹 = 一个持久化事务**（新包裹、进度计数、崩溃标记同事务提交）；密文、摘要、关联数据永不改变。
- 新主密钥在整个轮换期间只是 `staged`；只有 `rewrapped == total` 且零记录仍挂在旧 kid 上时，才在**同一个终止事务**里：激活新主密钥 → 旧主密钥置 `retired` → 轮换置 `done`。事务内有不变量校验（恰好一个 active 密钥）。
- 进程在任一点中断重启：每条记录按其行上的 kid 选择主密钥解包；旧主密钥在轮换完成前始终保留，因此**半轮换状态下全部档案依旧可读**。
- 稳定操作标识 `op_id`：同参重传 → 幂等重放（并续跑未完成轮换）；异参复用 → **HTTP 409，状态零推进**。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 档案员控制台（录入文本、发起/重放轮换、查看摘要/包裹版本/进度） |
| POST | `/api/records` | `{"text": "..."}` 密封一条标定记录 |
| GET | `/api/records` | 读取全部记录（真实解密，返回内容、摘要、kid、包裹版本） |
| POST | `/api/rotations` | `{"op_id": "rot-0001", "expected_kid": 1?}` 发起或重放轮换 |
| GET | `/api/rotations/<op_id>` | 查询轮换进度 |
| GET | `/api/rotations` | running/recent 轮换 + 各主密钥状态 |
| GET | `${HEALTH_PATH}` | 健康检查（默认 `/healthz`，可配置） |
| POST | `/api/debug/failpoints` | 崩溃注入（需 `ALLOW_FAILPOINT=1`，仅用于验证恢复） |

## 配置（环境变量 / Compose 覆盖）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `APP_PORT` | `8080` | 页面/API 监听端口（容器内） |
| `HOST_PORT` | `8080` | 发布到宿主机的端口 |
| `HEALTH_PATH` | `/healthz` | 健康检查路径 |
| `DB_PATH` | `/data/archive.db` | SQLite 数据文件 |
| `RESUME_ON_BOOT` | `0` | 为 `1` 时进程启动自动续跑中断的轮换；默认由同一 `op_id` 重放恢复 |
| `ALLOW_FAILPOINT` | `0` | 允许崩溃注入接口（archive 镜像默认开启） |

## 运行

```bash
# 启动档案服务与页面
docker compose up -d --build archive
# 浏览器打开 http://localhost:8080 （HOST_PORT 可改）

# 完整验证：pytest → 镜像构建检查 → 含真实崩溃/重启/恢复的 API 冒烟
docker compose run --build verify
echo "verify exit code: $?"
```

verify 容器依次执行并以退出码结束：

1. **代码测试**：`pytest`（含 fork 子进程硬崩溃后从同一 DB 重启恢复的用例）；
2. **镜像构建检查**：通过挂载的 Docker socket 执行 `docker compose build archive`；
3. **档案 API 冒烟**（`verify/smoke.py`）：密封 5 条记录 → 注入"第 3 条重包裹提交后 `os._exit(77)`"→ archive 容器被 `restart: unless-stopped` 真实重启 → 校验半轮换状态下 5 条全部可读、密文/摘要字节不变、旧密钥仍 active/新密钥仅 staged → 同一 `op_id` 重放完成轮换、新密钥激活旧密钥清退 → 校验同参重放幂等、异参 409 且不推进。

ARM64 主机构建 verify 镜像时传 `ARCH=aarch64`（Compose build arg）。

## 本地（无 Docker）

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-test.txt
.venv/bin/python -m pytest -q
APP_PORT=8080 DB_PATH=/tmp/archive.db .venv/bin/python -m app.server
```

## 目录

```
app/crypto.py      AES-256-GCM 记录加密与 DEK 包裹
app/store.py       SQLite 持久化 + 可恢复轮换状态机
app/web.py         Flask API 与控制台
app/server.py      waitress 入口
verify/            verify 镜像、入口与端到端冒烟
tests/             单元/API/崩溃恢复测试
compose.yaml       archive + verify 两个服务
```
