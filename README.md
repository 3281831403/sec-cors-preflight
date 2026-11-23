# sec-cors-preflight

## 题面

接口只给自家前端开的跨域权限，第三方站点却能直接读到返回数据：默认端口没有归一，带 443 和不带 443 的同一个域被判成两个；origin 匹配用 endswith，evil-a.com 命中 a.com；null origin 也被放行；方法白名单是星号时把带凭证的请求也当允许；请求头白名单用前缀比较，x-custom-evil 命中 x-custom；预检把请求里的 Access-Control-Request-Headers 原样反射回响应；实际请求响应缺少 Vary Origin，缓存会把放行头带给别人；允许任意 origin 的同时又回凭证为真，配置自相矛盾；策略校验不检查反射 origin 这种写法；批量判定复用响应头，后一个请求沿用前一个请求的放行结果。cors/preflight.py 是核心，tests/test_preflight.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态是可直接运行的失败环境：`cors/preflight.py` 中 8 个公开函数都是抛出 `NotImplementedError` 的桩，因此结果应恰好为 `15 failed`，不能出现 collection error，也不能出现 import 或 syntax error。

测试不联网、不使用随机数、不依赖系统时钟；只使用 Python 标准库 `urllib.parse` 和 pytest。`tests/test_preflight.py` 是验收基准，不可修改；不要删除测试、跳过测试或放宽断言，只实现 `cors/preflight.py`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 接口约定

策略是普通映射：

```python
{
    "allow_origins": ["https://app.example.com", "https://*.example.net"],
    "allow_methods": ["GET", "POST"],
    "allow_headers": ["content-type", "x-custom"],
    "allow_credentials": False,
    "reflect_origin": False,
}
```

请求也是普通映射：`origin` 必填，预检请求另带 `method` 和可选的 `headers`。响应统一为：

```python
{"allowed": bool, "status": int, "headers": {"Header-Name": "value"}}
```

- `normalize_origin`：scheme、host 小写，去掉 http 的 80 与 https 的 443 默认端口；非默认端口保留；不接受 userinfo、路径、查询、片段、`null`。Origin 容差为 0，匹配时 scheme、host、port 必须全等。
- `origin_allowed`：只接受精确 origin、字面 `*`、或 `https://*.example.com` 形式的显式子域模式；模式只匹配一级子域，不匹配 apex，也不做后缀/前缀匹配；`null` 永不放行。
- `allow_method`：方法名大小写敏感；凭证开启时 `*` 不授权任何具体方法，必须显式列出。
- `allow_header`：字段名大小写不敏感但必须完整相等；`x-custom-evil` 不得命中 `x-custom`；不支持通配请求头。
- `respond_preflight`：来源、方法、每个请求头全部通过才放行；拒绝返回 `allowed=False`、`status=403`、`headers={}`；成功返回 204，且只回显已校验的请求头。
- `respond_actual`：只校验来源，成功与拒绝都带 `Vary: Origin`；拒绝仍为 HTTP 200 但不返回任何 `Access-Control-Allow-Origin`；凭证开启时绝不输出 `Allow-Origin: *`。
- `validate_policy`：返回问题字符串列表，安全策略返回 `[]`；问题码以 `reflect_origin:`、`wildcard_origin_with_credentials:`、`wildcard_method_with_credentials:`、`wildcard_header_with_credentials:`、`null_origin:`、`invalid_origin:`、`invalid_policy:` 开头。
- `cors_batch`：返回 `{"responses": [...], "allowed": [...]}`，每个请求独立计算，结果与单独调用对应 `respond_*` 完全相同，不共享任何响应头。

## 目录

```text
sec-cors-preflight/
  README.md
  conftest.py
  .gitignore
  cors/__init__.py
  cors/preflight.py
  tests/test_preflight.py
```
