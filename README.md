# Cloudflare 可用节点探测（两段式）

自动判断一批 `IP:端口` 是否是“可用”的 Cloudflare 节点，并可通过 GitHub Actions 定时跑。

## 判断逻辑（两批）

1. **第一批 · TLS 探测**：对每个 `IP:端口` 发起 TCP 连接并完成 TLS 握手（SNI 为 `www.cloudflare.com`），
   校验对端返回的服务器证书**包含 `www.cloudflare.com`**（CN 或 SAN）。命中者保留。
2. **第二批 · HTTP 探测**：对第一批保留的节点发起 `GET /` 请求，请求头（及 SNI）为 `Host: crypto.cloudflare.com`，
   响应状态码为 **301** 的节点判定为可用。

只有**两批都通过**的节点才会写入可用列表：

```
第一批(TLS证书 www.cloudflare.com 通过)  →  第二批(HTTP Host: crypto.cloudflare.com 返回 301)  →  可用
```

> 说明：本机验证时 `162.159.136.79:443` 两段均通过被判定可用；
> 部分边缘节点证书虽含 `www.cloudflare.com`，但对 `crypto.cloudflare.com` 返回 403，
> 会被第二批正确过滤掉 —— 这正是两段式判断的意义。

## 文件

| 文件 | 作用 |
| --- | --- |
| `cloudflare_probe.py` | 探测脚本，仅依赖 Python 标准库 |
| `nodes.txt` | **候选节点列表，定时任务自动读取此文件探测**（维护这个文件即可） |
| `README.md` | 本文档 |
| `nodes.example.txt` | 示例候选节点列表（带 `#KR(...)` 附加信息） |
| `.github/workflows/cf_probe.yml` | GitHub Actions 定时自动化 |
| `.gitignore` | 忽略 `results/`、`__pycache__/` |

## 本地运行

```bash
# 1) 从候选文件探测（每行 ip 或 ip:port，# 开头为注释，IPv6 用 [addr]:port）
python cloudflare_probe.py --input nodes.txt

# 2) 直接粘贴节点列表（逗号/换行分隔；# 后的附加信息如 #KR(56.08Mbps,...) 自动忽略）
python cloudflare_probe.py \
  --nodes "171.103.22.35:10616#TH(11.45Mbps,...),211.37.103.158:11201#KR(56.08Mbps,...)"

# 3) 自动从 Cloudflare 官方 IP 段采样 2000 个候选 IP，探测 443/2053 两个端口
python cloudflare_probe.py --generate 2000 --ports 443,2053 --workers 200

# 4) 完整参数
python cloudflare_probe.py --input nodes.txt \
    --out usable_nodes.txt --report probe_report.txt \
    --workers 200 --timeout 5 \
    --probe-host crypto.cloudflare.com --expect-code 301 --scheme https
```

> **非标端口**：端口不限 443，`ip:port` 里写什么就探什么
> （如 `171.103.22.35:10616`）。列表带 `#KR(...)` 之类附加信息的可直接粘贴，
> 解析时 `#` 之后的内容会被自动丢弃，注释括号内的逗号不会误拆。

常用参数：

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `--input FILE` | 候选节点文件 | 与 `--generate` 二选一 |
| `--nodes LIST` | 直接粘贴节点列表（逗号/换行分隔），优先于其余方式 | — |
| `--generate N` | 从 Cloudflare 官方 IPv4 段采样 N 个 IP 作为候选 | — |
| `--ports` | 生成模式下的端口，逗号分隔 | `443` |
| `--port` | 输入文件中无端口时的默认端口 | `443` |
| `--out FILE` | 可用节点输出（每行 `ip:port`） | `usable_nodes.txt` |
| `--report FILE` | 全部节点两段探测明细 | `probe_report.txt` |
| `--workers N` | 并发数 | `100` |
| `--timeout S` | 单节点每段超时 | `5` |
| `--probe-host` | 第二批 Host/SNI | `crypto.cloudflare.com` |
| `--expect-code` | 第二批期望状态码 | `301` |
| `--scheme` | 第二批协议 `https` / `http` | `https` |

## GitHub Actions 自动化

工作流 `.github/workflows/cf_probe.yml`：

- **定时**：每 6 小时自动运行一次（cron `15 */6 * * *`，UTC），**默认自动读取仓库根目录的 `nodes.txt`** 探测。
- **候选来源优先级**（每次运行时按以下顺序选择）：
  1. 手动触发时填的 `nodes` 输入框；
  2. 仓库内的 `nodes.txt`（存在则自动读取，定时任务默认走这里）；
  3. `generate` 采样兜底：从 Cloudflare 官方 IPv4 段采样 `generate` 个 IP 探测；
  4. `generate=0` 时复用上次保存的 `results/candidates.txt`。
- **手动**：Actions 页面 → Cloudflare 可用节点探测 → Run workflow，可填
  - `nodes`：临时粘贴要探测的节点列表（逗号/换行分隔，可带 `#注释`）；
  - `generate`、`ports`、`workers`、`timeout`（`nodes` 为空且无 `nodes.txt` 时生效）。

运行后：

- 结果写入 `results/`（`usable_nodes.txt` / `probe_report.txt` / `candidates.txt` / 历史快照）。
- 自动上传为 **Artifact**（`cf-probe-results`，可在 Actions 页面下载）。
- 自动推送到独立分支 **`cf-probe-results`**，每轮提交一次（该分支可随时下拉最新可用节点）：

```bash
git fetch origin cf-probe-results
git show origin/cf-probe-results:results/usable_nodes.txt
```

`results/` 已加入 `.gitignore`，不会污染主分支。

### 注意事项

- 探测目标是 Cloudflare 官方公开的 IP 段，仅做 TLS 证书查看与普通 HTTP 请求，属常规网络连通性检测；
  请控制并发与频率，避免对目标网络造成压力。
- 若默认分支为受保护分支，结果推送分支同样可能被限制；此时仍可从 Artifact 下载结果。
- 如需探测 IPv6 节点，可自行在 `--input` 中用 `[addr]:port` 提供候选。
