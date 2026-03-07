# SecLens Collectors

面向社区贡献者的安全情报采集器仓库。采集器从公开源抓取数据，标准化后通过 SecLens Ingest API 投递到服务端。

- 主项目（服务端）：<https://github.com/seclens/SecLens>
- 本仓库（采集器）：<https://github.com/seclens/seclens-collectors>

## 仓库目标

每个采集器都是独立脚本，职责固定：
1. 抓取外部数据源
2. 转换为统一 JSON 结构
3. 通过 Token 投递到 SecLens

你可以只启用 1 个采集器，也可以批量启用多个采集器。

## 快速开始

```bash
git clone https://github.com/seclens/seclens-collectors.git
cd seclens-collectors

python3 -m venv .venv
source .venv/bin/activate

# 先安装你要运行的采集器依赖（示例：the_hacker_news）
pip install -r collectors/the_hacker_news/requirements.txt

# 配置服务端地址与 Token
cat > .env <<'EOF'
SECLENS_URL=https://seclens.info
SECLENS_TOKEN=slct_xxx
EOF

# 复制 profile 模板（工作文件 default.json 不纳入 git）
cp profiles/default.example.json profiles/default.json

# 预览本轮会跑哪些采集器
python run_collectors.py --profile profiles/default.json --dry-run

# 执行一轮
python run_collectors.py --profile profiles/default.json
```

## Ingest API 数据格式

投递接口：`POST /v1/ingest/bulletins`

```json
[
  {
    "source": {
      "source_slug": "the_hacker_news",
      "external_id": "unique-id",
      "origin_url": "https://example.com/article",
      "manifest": {
        "name": "The Hacker News Collector",
        "version": "1.0.0",
        "slug": "the_hacker_news"
      },
      "manifest_hash": "sha256-hex",
      "manifest_version": "1.0.0"
    },
    "content": {
      "title": "标题",
      "summary": "摘要",
      "published_at": "2026-03-07T02:00:00Z",
      "language": "en"
    },
    "fetched_at": "2026-03-07T02:05:00Z",
    "labels": ["security-news"],
    "topics": ["vulnerability"]
  }
]
```

返回示例：`{"accepted": 1, "duplicates": 0}`

### Manifest 同步机制（推荐）

- 每个采集器目录维护 `manifest.json`。
- 采集器每次投递都附带 `source.manifest`、`source.manifest_hash`、`source.manifest_version`。
- 服务端会按 `source_slug` 自动 upsert 数据源元信息；当 `manifest_hash` 变化时，会切换到新的当前版本记录。
- 这样主项目与采集器仓库可独立演进，不需要服务端直接读取采集器目录。

## 调度模型（重要）

当前采用“二层调度”：
1. `cron/systemd timer` 只负责周期唤醒（建议每 5 分钟）。
2. `run_collectors.py` 根据每个插件的周期和锚点判断“到期才执行”。

这样可以：
- 按插件设置不同周期
- 设置首次触发时间，错峰运行
- 避免整点全部同时启动

### 采集器端工作架构图（ASCII）

```text
                  +-----------------------------+
                  |   systemd timer / cron      |
                  |   (建议每 5 分钟唤醒一次)     |
                  +--------------+--------------+
                                 |
                                 v
                  +-----------------------------+
                  |        run_collectors.py    |
                  |  - 读取 profile/default.json |
                  |  - 计算每个插件是否到期       |
                  |  - 合并全局/插件级 env        |
                  +------+------------------+----+
                         |                  |
               due=YES   |                  | due=NO
                         v                  v
          +---------------------------+   +------------------+
          | 启动插件子进程 collector.py |   | 本轮跳过该插件    |
          +-------------+-------------+   +------------------+
                        |
                        v
          +---------------------------+
          | 抓取外部源 -> 结构化数据   |
          +-------------+-------------+
                        |
                        v
          +---------------------------+
          | POST /v1/ingest/bulletins |
          | Authorization: Bearer ... |
          +-------------+-------------+
                        |
                        v
          +---------------------------+
          | SecLens 服务端去重/入库    |
          +-------------+-------------+
                        |
                        v
          +---------------------------+
          | 更新 state_file next_due  |
          +---------------------------+
```

## Profile 配置格式（给用户/LLM）

模板文件是 `profiles/default.example.json`。  
实际运行请复制为 `profiles/default.json`（该文件是本地工作文件，不会被 `git pull` 覆盖）。

### 完整字段模板

```json
{
  "run_mode": "enabled_only",
  "enabled": [],
  "disabled": [],
  "concurrency": 1,
  "timeout_seconds": 300,
  "continue_on_error": true,
  "dry_run": false,
  "env": {},
  "state_file": ".state/scheduler_state.json",
  "default_interval_minutes": 60,
  "min_interval_minutes": 30,
  "schedule_overrides": {}
}
```

### 字段说明

- `run_mode`：
  - `enabled_only` 只跑 `enabled`
  - `all_except_disabled` 跑全部，排除 `disabled`
- `enabled`：启用的插件 slug 列表
- `disabled`：禁用的插件 slug 列表
- `concurrency`：并发执行数量
- `timeout_seconds`：单插件超时时间
- `continue_on_error`：单插件失败后是否继续其他插件
- `dry_run`：只展示调度结果，不真正执行
- `env`：全局环境变量，注入到所有插件
- `state_file`：调度状态文件（保存 `next_due_at` 等）
- `default_interval_minutes`：默认周期（分钟）
- `min_interval_minutes`：最小周期保护（分钟）
- `schedule_overrides`：插件级覆盖配置

### `schedule_overrides` 子结构

```json
{
  "the_hacker_news": {
    "interval_minutes": 30,
    "anchor_utc": "2026-03-07T02:10:00Z",
    "env": {
      "HTTP_PROXY": "http://192.168.15.88:8080",
      "HTTPS_PROXY": "http://192.168.15.88:8080",
      "NO_PROXY": "127.0.0.1,localhost,seclens.info"
    }
  }
}
```

- `interval_minutes`：该插件周期（分钟）
- `anchor_utc`：该插件锚点时间（UTC，ISO8601）
- `env`：插件级环境变量（默认不配置，即不使用代理）

## 周期优先级

同一个插件最终周期按以下优先级确定（高到低）：
1. 环境变量覆盖：`COLLECTOR_<SLUG>_INTERVAL_MINUTES`
2. `schedule_overrides.<slug>.interval_minutes`
3. `collectors/<slug>/config.example.yaml` 中的推荐周期
4. `default_interval_minutes`

锚点优先级类似：
1. `COLLECTOR_<SLUG>_ANCHOR_UTC`
2. `schedule_overrides.<slug>.anchor_utc`
3. `default_anchor_utc`（如配置）
4. 系统根据 slug 自动生成稳定锚点

## 代理配置（插件级，默认关闭）

默认：所有插件不使用代理。

如果某个插件必须走代理，只在该插件下配置 `env`。

- 当前白名单允许键：
  - `HTTP_PROXY` `HTTPS_PROXY` `ALL_PROXY` `NO_PROXY`
  - `http_proxy` `https_proxy` `all_proxy` `no_proxy`
- 使用了非白名单键会直接报错，防止误注入敏感变量。

## 常用配置用例

### 用例 1：只启用一个插件

```json
{
  "run_mode": "enabled_only",
  "enabled": ["the_hacker_news"],
  "disabled": [],
  "concurrency": 1,
  "timeout_seconds": 300,
  "continue_on_error": true,
  "dry_run": false,
  "env": {},
  "state_file": ".state/scheduler_state.json",
  "default_interval_minutes": 60,
  "min_interval_minutes": 30,
  "schedule_overrides": {
    "the_hacker_news": {
      "interval_minutes": 30,
      "anchor_utc": "2026-03-07T02:00:00Z"
    }
  }
}
```

### 用例 2：两个插件错峰

```json
{
  "run_mode": "enabled_only",
  "enabled": ["the_hacker_news", "cloudflare_blog"],
  "disabled": [],
  "concurrency": 1,
  "timeout_seconds": 300,
  "continue_on_error": true,
  "dry_run": false,
  "env": {},
  "state_file": ".state/scheduler_state.json",
  "default_interval_minutes": 60,
  "min_interval_minutes": 30,
  "schedule_overrides": {
    "the_hacker_news": {
      "interval_minutes": 30,
      "anchor_utc": "2026-03-07T02:00:00Z"
    },
    "cloudflare_blog": {
      "interval_minutes": 60,
      "anchor_utc": "2026-03-07T02:25:00Z"
    }
  }
}
```

### 用例 3：仅一个插件走代理

```json
{
  "run_mode": "enabled_only",
  "enabled": ["the_hacker_news", "cloudflare_blog"],
  "disabled": [],
  "concurrency": 1,
  "timeout_seconds": 300,
  "continue_on_error": true,
  "dry_run": false,
  "env": {},
  "state_file": ".state/scheduler_state.json",
  "default_interval_minutes": 60,
  "min_interval_minutes": 30,
  "schedule_overrides": {
    "the_hacker_news": {
      "interval_minutes": 30,
      "anchor_utc": "2026-03-07T02:00:00Z"
    },
    "cloudflare_blog": {
      "interval_minutes": 60,
      "anchor_utc": "2026-03-07T02:10:00Z",
      "env": {
        "HTTP_PROXY": "http://192.168.15.88:8080",
        "HTTPS_PROXY": "http://192.168.15.88:8080"
      }
    }
  }
}
```

## systemd 定时运行（推荐）

```bash
sudo cp docs/systemd/seclens-collectors.service /etc/systemd/system/
sudo cp docs/systemd/seclens-collectors.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now seclens-collectors.timer

# 手工触发一次
sudo systemctl start seclens-collectors.service

# 查看日志
sudo journalctl -u seclens-collectors.service -f
```

## 常用命令

```bash
# 查看可用插件
python run_collectors.py --list

# 只看调度决策（不执行）
python run_collectors.py --profile profiles/default.json --dry-run

# 执行一轮
python run_collectors.py --profile profiles/default.json
```

## 贡献说明

请参考：[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)

## License

MIT
