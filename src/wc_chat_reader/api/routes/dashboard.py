"""Interactive API debug console (API 接口与调试).

Serves a single self-contained HTML page at ``GET /`` that lets non-technical
users exercise every query endpoint — sessions, chatrooms, contacts and the
chat log itself — from a browser, without writing a single ``curl`` command.

Design notes
------------
* The HTML is embedded as a string so the feature adds **zero** dependencies
  and zero on-disk assets. Everything (markup + CSS + JS) ships in one
  response, mirroring how chatlog ships its debug console.
* The page is intentionally served **without** ``require_auth``: it is just a
  static shell. If the operator configured ``api_token``, the page prompts
  for it once and forwards it as a ``Bearer`` header on every fetch — the
  token never leaves the user's own browser.
* No ``Cache-Control`` games: the page is tiny and always fresh.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["dashboard"])

# ruff: noqa: RUF001,E501  (page copy intentionally uses full-width CJK punctuation;
# long lines are fine inside an embedded HTML/CSS/JS document)
_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API 接口与调试 · wc-chat-reader</title>
<style>
  :root {
    --accent: #07c160;          /* WeChat green */
    --accent-dark: #06ad56;
    --primary: #3a7afe;
    --bg: #f5f6f7;
    --card: #ffffff;
    --border: #e3e5e7;
    --text: #1f2329;
    --muted: #8a8f99;
    --mono: ui-monospace, "Cascadia Mono", Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px 16px 64px;
    background: var(--bg); color: var(--text);
    font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
  }
  .wrap { max-width: 860px; margin: 0 auto; }
  h1 { font-size: 20px; margin: 0 0 4px; display: flex; align-items: center; gap: 8px; }
  h1 .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 18px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; }
  .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); margin-bottom: 18px; flex-wrap: wrap; }
  .tab {
    padding: 9px 18px; cursor: pointer; border: none; background: none;
    font-size: 14px; color: var(--muted); border-bottom: 2px solid transparent;
  }
  .tab.active { color: var(--text); border-bottom-color: var(--accent); font-weight: 600; }
  .endpoint { font-family: var(--mono); font-size: 12px; color: var(--primary);
              background: #eef3ff; padding: 2px 8px; border-radius: 4px; }
  .desc { font-size: 13px; color: var(--muted); margin: 10px 0 16px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .field { margin-bottom: 14px; }
  .field label { display: block; font-size: 13px; margin-bottom: 5px; }
  .field label .req { color: #d03050; margin-left: 2px; }
  .field label .opt { color: var(--muted); font-size: 12px; margin-left: 6px; }
  .field input, .field select {
    width: 100%; padding: 8px 10px; font-size: 13px;
    border: 1px solid var(--border); border-radius: 6px; background: #fff;
  }
  .field input:focus, .field select:focus { outline: 1px solid var(--accent); border-color: var(--accent); }
  .btn {
    padding: 9px 22px; font-size: 14px; border: none; border-radius: 6px;
    background: var(--primary); color: #fff; cursor: pointer;
  }
  .btn:hover { filter: brightness(1.07); }
  .btn:disabled { opacity: .55; cursor: default; }
  .btn.green { background: var(--accent); }
  .btn.green:hover { background: var(--accent-dark); }
  .urlbar {
    display: flex; gap: 8px; align-items: center; margin-top: 18px;
    background: #f2f3f5; border: 1px solid var(--border); border-radius: 6px;
    padding: 8px 12px; font-family: var(--mono); font-size: 12px; word-break: break-all;
  }
  .urlbar code { flex: 1; }
  .result {
    margin-top: 14px; background: #fafbfc; border: 1px solid var(--border);
    border-radius: 6px; padding: 14px; font-family: var(--mono); font-size: 12.5px;
    white-space: pre-wrap; word-break: break-word; max-height: 460px; overflow: auto;
    min-height: 60px;
  }
  .result:empty::before { content: "结果会显示在这里"; color: var(--muted); }
  .row { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; }
  .err { color: #d03050; }
  .ok  { color: var(--accent-dark); }
  .authbar { margin-top: 22px; font-size: 12px; color: var(--muted); display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .authbar input { width: 260px; padding: 5px 8px; font-size: 12px; border: 1px solid var(--border); border-radius: 5px; }
  details { margin-top: 4px; }
  summary { cursor: pointer; }
</style>
</head>
<body>
<div class="wrap">
  <h1><span class="dot"></span>API 接口与调试</h1>
  <div class="sub">在浏览器里直接调用 wc-chat-reader 的 HTTP API —— 无需命令行。</div>

  <div class="card">
    <div class="tabs" id="tabs"></div>
    <div class="desc"><span id="tabDesc"></span><span class="endpoint" id="tabEp"></span></div>
    <form id="form" autocomplete="off"></form>
    <button class="btn" id="run" type="button">执行查询</button>

    <div class="urlbar" id="urlbar" hidden>
      <code id="urlText"></code>
      <button class="btn green" type="button" id="copyUrl">复制请求URL</button>
    </div>

    <div class="result" id="result"></div>
    <div class="row">
      <span id="status"></span>
      <button class="btn green" type="button" id="copyResult" hidden>复制结果</button>
    </div>
  </div>

  <div class="authbar">
    <details>
      <summary>🔑 认证设置（仅当服务器配置了 api_token 时需要）</summary>
      <div style="margin-top:8px">
        Bearer Token: <input id="token" type="password" placeholder="留空表示无认证">
      </div>
    </details>
  </div>
</div>

<script>
const TABS = [
  { id: "session", label: "最近会话", ep: "/api/v1/session",
    desc: "查询最近会话列表。", fields: [
      { name: "format", label: "输出格式", type: "select", options: ["", "json"], placeholder: "默认" },
    ] },
  { id: "chatroom", label: "群聊", ep: "/api/v1/chatroom",
    desc: "查询群聊列表，可选择性地按关键词搜索。", fields: [] },
  { id: "contact", label: "联系人", ep: "/api/v1/contact",
    desc: "查询联系人列表。", fields: [] },
  { id: "chatlog", label: "聊天记录", ep: "/api/v1/chatlog",
    desc: "查询指定时间范围内与特定联系人或群聊的聊天记录。", fields: [
      { name: "time", label: "时间范围", required: true,
        placeholder: "例如：2023-01-01 或 2023-01-01~2023-01-31" },
      { name: "talker", label: "聊天对象", required: true,
        placeholder: "wxid、群ID、备注名或昵称" },
      { name: "sender", label: "发送者", placeholder: "指定消息发送者" },
      { name: "keyword", label: "关键词", placeholder: "搜索消息内容中的关键词" },
      { name: "limit", label: "返回数量", placeholder: "默认 100，最大 10000" },
      { name: "offset", label: "偏移量", placeholder: "默认 0" },
      { name: "format", label: "输出格式", type: "select",
        options: ["", "text", "json", "csv"], placeholder: "默认（text）" },
    ] },
];

const $ = (id) => document.getElementById(id);
let active = TABS[0];

function renderTabs() {
  $("tabs").innerHTML = "";
  for (const t of TABS) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tab" + (t === active ? " active" : "");
    b.textContent = t.label;
    b.onclick = () => { active = t; renderTabs(); renderForm(); };
    $("tabs").appendChild(b);
  }
  $("tabDesc").textContent = active.desc;
  $("tabEp").textContent = "GET " + active.ep;
}

function renderForm() {
  const f = $("form");
  f.innerHTML = "";
  for (const fld of active.fields) {
    const div = document.createElement("div");
    div.className = "field";
    const lab = document.createElement("label");
    lab.textContent = fld.label + "：";
    if (fld.required) {
      const r = document.createElement("span"); r.className = "req"; r.textContent = "*";
      lab.appendChild(r);
    } else {
      const o = document.createElement("span"); o.className = "opt"; o.textContent = "可选";
      lab.appendChild(o);
    }
    div.appendChild(lab);
    let inp;
    if (fld.type === "select") {
      inp = document.createElement("select");
      for (const opt of fld.options) {
        const o = document.createElement("option");
        o.value = opt; o.textContent = opt === "" ? (fld.placeholder || "默认") : opt;
        inp.appendChild(o);
      }
    } else {
      inp = document.createElement("input");
      inp.placeholder = fld.placeholder || "";
    }
    inp.name = fld.name;
    div.appendChild(inp);
    f.appendChild(div);
  }
  if (active.fields.length === 0) {
    const p = document.createElement("div");
    p.className = "desc"; p.textContent = "此接口无需参数，直接执行即可。";
    f.appendChild(p);
  }
  $("result").textContent = "";
  $("urlbar").hidden = true;
  $("copyResult").hidden = true;
  $("status").textContent = "";
}

function buildUrl() {
  const params = new URLSearchParams();
  const data = new FormData($("form"));
  for (const [k, v] of data.entries()) {
    if (v !== null && String(v).trim() !== "") params.set(k, String(v).trim());
  }
  const qs = params.toString();
  return location.origin + active.ep + (qs ? "?" + qs : "");
}

async function run() {
  const url = buildUrl();
  $("urlText").textContent = url;
  $("urlbar").hidden = false;
  $("run").disabled = true;
  $("status").textContent = "请求中…";
  $("status").className = "";
  const headers = {};
  const tok = $("token").value.trim();
  if (tok) headers["Authorization"] = "Bearer " + tok;
  try {
    const resp = await fetch(url, { headers });
    const text = await resp.text();
    let pretty = text;
    try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch (_) { /* not JSON */ }
    $("result").textContent = pretty;
    $("copyResult").hidden = false;
    $("status").textContent = resp.ok ? ("HTTP " + resp.status + " · " + pretty.length + " 字符")
                                      : ("HTTP " + resp.status + " · 请求失败");
    $("status").className = resp.ok ? "ok" : "err";
  } catch (e) {
    $("result").textContent = "请求失败：" + e;
    $("status").textContent = "网络错误";
    $("status").className = "err";
  } finally {
    $("run").disabled = false;
  }
}

function copy(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const old = btn.textContent;
    btn.textContent = "已复制 ✓";
    setTimeout(() => { btn.textContent = old; }, 1200);
  });
}

$("run").onclick = run;
$("copyUrl").onclick = (e) => copy($("urlText").textContent, e.target);
$("copyResult").onclick = (e) => copy($("result").textContent, e.target);
$("token").value = localStorage.getItem("wcr_token") || "";
$("token").oninput = (e) => localStorage.setItem("wcr_token", e.target.value);

renderTabs();
renderForm();
</script>
</body>
</html>
"""


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard() -> HTMLResponse:
    """Serve the interactive API debug console.

    Deliberately unauthenticated: the page is a static shell. Any configured
    ``api_token`` is supplied by the user in the page itself and forwarded
    by the browser on each API call.
    """
    return HTMLResponse(content=_PAGE)
