# sec-cors-preflight

## 题面

接口只给自家前端开的跨域权限，第三方站点却能直接读到返回数据：默认端口没有归一，`https://app.example.com:443` 与白名单里的 `https://app.example.com` 被当成两个来源或反向放行；来源校验用后缀匹配，`https://evil-a.com` 能命中 `https://a.com`；`null` 来源被当成合法来源；凭证请求下 `*` 仍然放行任意方法，而浏览器对携带凭证的 `*` 本就不认；请求头用前缀匹配，`x-custom-evil` 能命中 `x-custom`；预检把未校验的 `Access-Control-Request-Headers` 原样反射；实际响应缺少 `Vary: Origin`，共享缓存会把别人的放行头串给第三方；返回 `Allow-Origin: *` 时还带着 `Allow-Credentials: true`，浏览器拒绝而配置层却留下凭证泄漏面；策略校验不识别“反射请求 origin”这种配置；批量判定复用上一请求的响应头，第二个来源拿到第一个来源的 `Allow-Origin`。cors/preflight.py 是核心，tests/test_preflight.py 15个红。要修的是：按 scheme/host/port 归一来源并做精确匹配与受控子域匹配，拒绝 `null` 与后缀混淆，凭证场景禁用 `*` 并逐项校验方法与请求头，预检不得反射未授权头且拒绝时返回 403 语义，实际响应始终带 `Vary: Origin` 且绝不把 `*` 与凭证混用，策略校验拦截 `*`+凭证、反射 origin 与 `*` 方法+凭证，批量每个请求独立计算。

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
