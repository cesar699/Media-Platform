#!/usr/bin/env python3
"""
video-dl-web: 网页版视频搜索下载器 (单用户个人使用)。

    python3 app.py [端口, 默认 5000]

流程: 粘贴链接或输关键词 -> 自动搜出视频列表 -> 勾选 -> 下载。
"""
import json
import mimetypes
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import uuid
import http.cookiejar

import requests
import requests.cookies
import yt_dlp
from flask import Flask, jsonify, render_template, request, send_file, Response, stream_with_context

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DL_DIR = os.path.join(BASE_DIR, "downloads")
os.makedirs(DL_DIR, exist_ok=True)

jobs = {}  # job_id -> {status,total,done,files,errors,created}
MAX_JOBS = 100
COOKIE_FILE = os.path.join(BASE_DIR, "cookies.txt")
stream_cache = {}  # page_url -> {url, title, at}
STREAM_TTL = 1800
# gunicorn 用单 worker + 多线程 (gthread) 运行, 所有内存状态跨线程共享, 用锁保护
state_lock = threading.RLock()
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def ydl_base_opts(extra=None):
    """yt-dlp 通用选项: 有 Cookie 文件时自动带上。"""
    opts = {"quiet": True, "no_warnings": True}
    if os.path.isfile(COOKIE_FILE):
        opts["cookiefile"] = COOKIE_FILE
    if extra:
        opts.update(extra)
    return opts


def parse_cookies(domain, text):
    """把粘贴的 Cookie 转成 Netscape 格式。
    支持两种输入: 浏览器插件导出的 Netscape 文件内容,
    或 document.cookie 复制的 name=value;... 格式 (需配合 domain)。"""
    text = (text or "").strip()
    if not text:
        raise ValueError("Cookie 不能为空")
    lines = []
    if "Netscape HTTP Cookie File" in text or "\t" in text:
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    else:
        domain = (domain or "").strip().lstrip(".")
        if not domain or "." not in domain:
            raise ValueError("请填写正确的域名 (如 pornhub.com)")
        dot_domain = "." + domain
        for part in text.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name, value = name.strip(), value.strip()
            if not name:
                continue
            lines.append(f"{dot_domain}\tTRUE\t/\tTRUE\t0\t{name}\t{value}")
    if not lines:
        raise ValueError("没有解析到有效的 Cookie")
    return "# Netscape HTTP Cookie File\n" + "\n".join(lines) + "\n"


def validate_cookie_file(path):
    """校验 Cookie 文件可被正常加载, 坏文件会导致所有 yt-dlp 调用失败。"""
    jar = http.cookiejar.MozillaCookieJar(path)
    jar.load(ignore_discard=True, ignore_expires=True)


def prune_jobs():
    """防止 jobs 无限增长: 超过上限时先清掉最早完成的。"""
    with state_lock:
        if len(jobs) <= MAX_JOBS:
            return
        done = sorted(
            ((jid, j) for jid, j in jobs.items() if j["status"] == "done"),
            key=lambda kv: kv[1].get("created", 0))
        for jid, _ in done[:len(jobs) - MAX_JOBS]:
            jobs.pop(jid, None)

QUALITY_FORMATS = {
    "best": "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best",
    # 末尾的 /best 是兜底: 直接文件链接没有清晰度元数据时直接拿源文件
    "1080": ("bestvideo[height<=1080][ext=mp4]+bestaudio[ext=m4a]"
              "/best[height<=1080][ext=mp4]/best[height<=1080]/best"),
    "720": ("bestvideo[height<=720][ext=mp4]+bestaudio[ext=m4a]"
             "/best[height<=720][ext=mp4]/best[height<=720]/best"),
    "480": ("bestvideo[height<=480][ext=mp4]+bestaudio[ext=m4a]"
             "/best[height<=480][ext=mp4]/best[height<=480]/best"),
}

UA_MOBILE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
             "Mobile/15E148 Safari/604.1")


def build_target(query, site):
    q = query.strip()
    if q.startswith("http://") or q.startswith("https://"):
        return q
    if site == "pornhub":
        return ("https://www.pornhub.com/video/search?search="
                + urllib.parse.quote(q))
    return f"ytsearch10:{q}"


def search_videos(query, site):
    target = build_target(query, site)
    opts = ydl_base_opts({"extract_flat": True, "skip_download": True,
                          "playlistend": 30})
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(target, download=False)
    raw = info.get("entries") or []
    if info.get("_type") != "playlist":
        raw = [info]
    out = []
    for e in raw:
        if not e:
            continue
        out.append({
            "url": e.get("webpage_url") or e.get("url") or "",
            "title": e.get("title") or "(无标题)",
            "duration": e.get("duration"),
            "thumbnail": e.get("thumbnail") or "",
            "uploader": e.get("uploader") or e.get("channel") or "",
            "vid": e.get("id") or "",
        })
    return out


def run_job(jid, items, quality="best", clean=False):
    st = jobs[jid]
    fmt = QUALITY_FORMATS.get(quality, QUALITY_FORMATS["best"])

    def record(ok_file=None, err=None):
        with state_lock:
            if ok_file:
                st["files"].append(ok_file)
            if err:
                st["errors"].append(err)
            st["done"] += 1

    for it in items:
        url = it["url"]
        try:
            if clean and ("douyin.com" in url or "tiktok.com" in url):
                hit = try_douyin_nowm(url)
                if hit:
                    link, title = hit
                    download_direct(link, title)
                    record(ok_file=title + " (无水印)")
                    continue
            opts = ydl_base_opts({
                "format": fmt,
                "outtmpl": os.path.join(DL_DIR, "%(title).60s [%(id)s].%(ext)s"),
                "merge_output_format": "mp4"})
            with yt_dlp.YoutubeDL(opts) as ydl:
                ydl.extract_info(url, download=True)
            record(ok_file=it.get("title", ""))
        except Exception as e:  # noqa: BLE001 - report per-item failure
            record(err=f'{it.get("title", "")}: {e}')
    with state_lock:
        st["status"] = "done"


def try_douyin_nowm(url):
    """尝试从抖音官方接口拿无水印直链。成功返回 (直链, 标题), 失败返回 None。"""
    headers = {"User-Agent": UA_MOBILE}
    try:
        req = urllib.request.Request(url, headers=headers)
        final = urllib.request.urlopen(req, timeout=20).geturl()
    except Exception:
        return None
    m = re.search(r"/video/(\d+)", final)
    if not m:
        return None
    vid = m.group(1)
    api = f"https://www.iesdouyin.com/web/api/v2/aweme/iteminfo/?item_ids={vid}"
    try:
        req = urllib.request.Request(
            api, headers={**headers, "Referer": "https://www.iesdouyin.com/"})
        data = json.loads(urllib.request.urlopen(req, timeout=20).read())
        item = data["item_list"][0]
        play = item["video"]["play_addr"]["url_list"][0]
        nowm = play.replace("playwm", "play")
        title = re.sub(r'[\\/:*?"<>|]', "_", item.get("desc", vid)[:60])
        return nowm, title or vid
    except Exception:
        return None


def download_direct(url, title_hint="video"):
    """直接下载文件 URL (用于无水印直链)。带上 Cookie 会话, 失败时清理残留文件。"""
    safe = re.sub(r'[\\/:*?"<>|]', "_", title_hint)[:60] or "video"
    dest = os.path.join(DL_DIR, safe + ".mp4")
    headers = {"User-Agent": UA_MOBILE, "Referer": "https://www.iesdouyin.com/"}
    s = requests.Session()
    if os.path.isfile(COOKIE_FILE):
        try:
            jar = requests.cookies.MozillaCookieJar(COOKIE_FILE)
            jar.load(ignore_discard=True, ignore_expires=True)
            s.cookies = jar
        except Exception:
            pass
    try:
        with s.get(url, headers=headers, stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(256 * 1024):
                    if chunk:
                        f.write(chunk)
    except Exception:
        if os.path.exists(dest):
            os.remove(dest)
        raise
    return dest


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/search", methods=["POST"])
def api_search():
    data = request.get_json(force=True)
    query = (data.get("query") or "").strip()
    site = data.get("site") or "youtube"
    if not query:
        return jsonify({"ok": False, "error": "请输入链接或关键词"}), 400
    try:
        items = search_videos(query, site)
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"搜索失败: {e}"}), 500
    return jsonify({"ok": True, "items": items, "count": len(items)})


@app.route("/api/download", methods=["POST"])
def api_download():
    data = request.get_json(force=True)
    items = data.get("items") or []
    items = [i for i in items if i.get("url")]
    if not items:
        return jsonify({"ok": False, "error": "没有可下载的视频"}), 400
    quality = data.get("quality") or "best"
    clean = bool(data.get("clean"))
    jid = uuid.uuid4().hex[:12]
    with state_lock:
        jobs[jid] = {"status": "running", "total": len(items), "done": 0,
                     "files": [], "errors": [],
                     "quality": quality, "clean": clean,
                     "created": time.time()}
        prune_jobs()
    threading.Thread(target=run_job, args=(jid, items, quality, clean),
                     daemon=True).start()
    return jsonify({"ok": True, "job": jid, "total": len(items)})


@app.route("/api/job/<jid>")
def api_job(jid):
    with state_lock:
        st = jobs.get(jid)
        snap = ({k: (list(v) if isinstance(v, list) else v)
                 for k, v in st.items()} if st else None)
    if not snap:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    return jsonify({"ok": True, **snap})


@app.route("/api/cookies", methods=["GET", "POST", "DELETE"])
def api_cookies():
    """Cookie 管理: 登录态,用于会员/私密视频。
    POST {domain, text}: 保存; GET: 返回是否已设置(不返回内容);
    DELETE: 清除。"""
    if request.method == "GET":
        return jsonify({"ok": True,
                        "has_cookies": os.path.isfile(COOKIE_FILE)})
    if request.method == "DELETE":
        if os.path.isfile(COOKIE_FILE):
            os.remove(COOKIE_FILE)
        return jsonify({"ok": True})
    data = request.get_json(force=True)
    try:
        content = parse_cookies(data.get("domain"), data.get("text"))
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    with open(COOKIE_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(COOKIE_FILE, 0o600)
    try:
        validate_cookie_file(COOKIE_FILE)
    except Exception:
        os.remove(COOKIE_FILE)
        return jsonify({"ok": False, "error": "Cookie 格式无法识别，请检查后重试"}), 400
    return jsonify({"ok": True})


@app.route("/api/files")
def api_files():
    out = []
    total = 0
    for f in os.listdir(DL_DIR):
        p = os.path.join(DL_DIR, f)
        if os.path.isfile(p):
            sz = os.path.getsize(p)
            total += sz
            out.append({"name": f, "size": sz,
                        "mtime": os.path.getmtime(p)})
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return jsonify({"ok": True, "files": out, "total_size": total})


@app.route("/api/cleanup", methods=["POST"])
def api_cleanup():
    """删除 N 天前下载的文件 (默认 7 天), 防止磁盘被塞满。"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        days = int(data.get("days", 7))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "天数无效"}), 400
    days = max(1, min(days, 365))
    cutoff = time.time() - days * 86400
    removed = 0
    for f in os.listdir(DL_DIR):
        p = os.path.join(DL_DIR, f)
        if os.path.isfile(p) and os.path.getmtime(p) < cutoff:
            os.remove(p)
            removed += 1
    return jsonify({"ok": True, "removed": removed})


@app.route("/api/file/<name>", methods=["DELETE"])
def api_del_file(name):
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return jsonify({"ok": False, "error": "非法文件名"}), 400
    p = os.path.join(DL_DIR, name)
    if not os.path.isfile(p):
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    os.remove(p)
    return jsonify({"ok": True})


@app.route("/api/watch/<name>")
def api_watch(name):
    """在线预览: 以流式返回视频文件 (支持 Range 拖进度)。
    加 ?download=1 则作为附件下载到浏览器本地。"""
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return jsonify({"ok": False, "error": "非法文件名"}), 400
    p = os.path.join(DL_DIR, name)
    if not os.path.isfile(p):
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    mt, _ = mimetypes.guess_type(p)
    as_attach = request.args.get("download") == "1"
    return send_file(p, mimetype=mt or "video/mp4",
                     as_attachment=as_attach, conditional=True)


def get_direct_stream(page_url):
    """解析视频直链 (带 30 分钟缓存)。返回 (direct_url, title)。"""
    now = time.time()
    with state_lock:
        hit = stream_cache.get(page_url)
    if hit and now - hit["at"] < STREAM_TTL:
        return hit["url"], hit["title"]
    opts = ydl_base_opts({"skip_download": True, "noplaylist": True})
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(page_url, download=False)
    if not info or info.get("_type") == "playlist":
        raise ValueError("不支持播放列表直连，请先下载")
    fmts = [f for f in info.get("formats", []) if f.get("url")]
    both = [f for f in fmts
            if f.get("vcodec") != "none" and f.get("acodec") != "none"]
    pool = both or fmts
    if not pool:
        raise ValueError("解析不到可播放的视频流")
    pool.sort(key=lambda f: (f.get("height") or 0, f.get("tbr") or 0))
    direct = pool[-1]["url"]
    title = info.get("title", "视频")
    with state_lock:
        # 缓存裁剪，防止无限增长
        if len(stream_cache) > 200:
            stream_cache.clear()
        stream_cache[page_url] = {"url": direct, "title": title, "at": now}
    return direct, title


@app.route("/api/stream")
def api_stream():
    """直接播放: 解析直链后由服务器实时转发视频流给浏览器 (支持 Range 拖进度)。
    会员视频需先在 🍪 里保存 Cookie。"""
    page_url = (request.args.get("url") or "").strip()
    if not page_url.startswith(("http://", "https://")):
        return jsonify({"ok": False, "error": "无效的视频链接"}), 400
    try:
        direct_url, title = get_direct_stream(page_url)
    except Exception as e:
        return jsonify({"ok": False,
                        "error": "解析失败: " + str(e)[:200]}), 502
    if request.args.get("check") == "1":
        return jsonify({"ok": True, "title": title})
    headers = {"User-Agent": UA}
    rng = request.headers.get("Range")
    if rng:
        headers["Range"] = rng
    try:
        up = requests.get(direct_url, headers=headers,
                          stream=True, timeout=30)
    except Exception as e:
        return jsonify({"ok": False,
                        "error": "上游连接失败: " + str(e)[:200]}), 502
    if up.status_code >= 400:
        return jsonify({"ok": False,
                        "error": f"上游返回 {up.status_code}"}), 502
    pass_through = {}
    for k in ("Content-Type", "Content-Length",
              "Content-Range", "Accept-Ranges"):
        if k in up.headers:
            pass_through[k] = up.headers[k]

    def gen():
        try:
            for chunk in up.iter_content(chunk_size=65536):
                if chunk:
                    yield chunk
        finally:
            up.close()

    return Response(stream_with_context(gen()),
                    status=up.status_code, headers=pass_through)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"serving on http://127.0.0.1:{port}  (下载目录: {DL_DIR})")
    app.run(host="127.0.0.1", port=port, debug=False)
