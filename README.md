# 液氙标定档案 · 崩溃安全的主密钥轮换

档案员在页面录入标定文本并创建密封记录；服务端以 **AES-256-GCM** 加密每条记录
（每条记录一个独立数据密钥 DEK），DEK 由当前主密钥包裹后入库。主密钥轮换只逐条
**重包裹 DEK**——密文、SHA-256 摘要与关联数据（AAD）在轮换前后逐比特不变。

## 运行

```bash
docker compose up --build
```

- `app`：档案服务 + 页面，暴露在可配置端口（默认 `8080`），健康路径可配置
  （默认 `/healthz`）。
- `verify`：一次性校验容器——依次执行代码测试（pytest）、镜像构建检查
  （挂载 `/var/run/docker.sock` 时执行真实 `docker build`，否则静态校验
  Dockerfile）、**轮换中断/恢复演练**（注入崩溃后重启恢复）、档案 API 冒烟，
  全部通过以退出码 0 结束，任一步失败以非零退出。

```bash
docker compose up --build --abort-on-container-exit   # verify 的退出码即结论
```

### 可配置项（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `APP_PORT` | `8080` | 服务监听端口（compose 同时映射到宿主机同端口） |
| `APP_HOST` | `0.0.0.0` | 监听地址 |
| `HEALTH_PATH` | `/healthz` | 健康检查路径（compose healthcheck 同步使用） |
| `DB_PATH` | 容器内 `/data/archive.db` | SQLite 数据库文件 |
| `ROTATION_STEP_DELAY_MS` | `0`（compose 中 150） | 每条重包裹之间的延迟，便于观察进度 |
| `ROTATION_CRASH_AFTER` | 无 | 测试钩子：提交第 N 条重包裹后进程立即退出（模拟中断） |
| `ROTATION_CRASH_OP` | 无 | 限定崩溃注入生效的操作标识 |

## 加密与持久化设计

- 记录密文：`AES-256-GCM(DEK, 标定文本)`，AAD = `lx-archive:v1:record:<id>`；
  摘要 = `SHA-256(明文)`。
- DEK 包裹：`AES-256-GCM(当前主密钥, DEK)`，AAD = `lx-archive:v1:dek-wrap:<id>`。
- SQLite（WAL + `synchronous=FULL`）。每条记录的重包裹与进度推进在**单个
  IMMEDIATE 事务**内提交；轮换收尾（激活新主密钥、删除旧主密钥、标记完成）
  也是单事务。进程在任意记录之后崩溃，重启时从持久化进度断点续跑；只有全部
  记录完成重包裹后，新主密钥才被激活、旧主密钥才被清退。
- 轮换期间旧主密钥保留，全部已提交档案始终可读；轮换进行中暂停密封新记录
  （`409`），避免新记录错过快照。

## API 摘要

| 方法/路径 | 说明 |
| --- | --- |
| `POST /api/records` | 密封记录 `{content, record_id?}` → `201`；轮换进行中或 ID 重复 → `409` |
| `GET /api/records` / `GET /api/records/{id}` | 记录元信息：摘要、包裹版本、AAD、轮换状态 |
| `POST /api/records/{id}/verify` | 端到端解密并校验摘要与 AAD |
| `POST /api/rotations` | 发起轮换 `{operation_id, target_version?}` → `201`；同参重传 → `200` 重放；异参复用 → `409` 且不推进状态 |
| `GET /api/rotations/{operation_id}` | 轮换进度（逐条状态、百分比） |
| `GET /api/state` | 当前主密钥版本、密钥表、记录数、进行中/最近轮换 |
| `GET <HEALTH_PATH>` | 健康检查 |

## 本地开发

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q tests          # 代码测试
.venv/bin/python -m app.main                 # 启动服务（http://127.0.0.1:8080）
.venv/bin/python -m verify.e2e_crash         # 中断/恢复演练
```
