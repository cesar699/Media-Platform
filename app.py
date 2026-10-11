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

import yt_dlp
from flask import Flask, jsonify, render_template, request, send_file

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DL_DIR = os.path.join(BASE_DIR, "downloads")
os.makedirs(DL_DIR, exist_ok=True)

jobs = {}  # job_id -> {status,total,done,files,errors,created}
MAX_JOBS = 100


def prune_jobs():
    """防止 jobs 无限增长: 超过上限时先清掉最早完成的。"""
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
    opts = {"quiet": True, "no_warnings": True, "extract_flat": True,
            "skip_download": True, "playlistend": 30}
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
    for it in items:
        url = it["url"]
        try:
            if clean and ("douyin.com" in url or "tiktok.com" in url):
                hit = try_douyin_nowm(url)
                if hit:
                    link, title = hit
                    download_direct(link, title)
                    st["files"].append(title + " (无水印)")
                    st["done"] += 1
                    continue
            opts = {"format": fmt,
                    "outtmpl": os.path.join(DL_DIR,
                                            "%(title).60s [%(id)s].%(ext)s"),
                    "merge_output_format": "mp4",
                    "quiet": True, "no_warnings": True}
            with yt_dlp.YoutubeDL(opts) as ydl:
                ydl.extract_info(url, download=True)
            st["files"].append(it.get("title", ""))
        except Exception as e:  # noqa: BLE001 - report per-item failure
            st["errors"].append(f'{it.get("title", "")}: {e}')
        st["done"] += 1
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
    """直接下载文件 URL (用于无水印直链)。失败时清理残留文件。"""
    safe = re.sub(r'[\\/:*?"<>|]', "_", title_hint)[:60] or "video"
    dest = os.path.join(DL_DIR, safe + ".mp4")
    headers = {"User-Agent": UA_MOBILE, "Referer": "https://www.iesdouyin.com/"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
            while True:
                chunk = r.read(1024 * 256)
                if not chunk:
                    break
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
    st = jobs.get(jid)
    if not st:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    return jsonify({"ok": True, **st})


@app.route("/api/files")
def api_files():
    out = []
    for f in os.listdir(DL_DIR):
        p = os.path.join(DL_DIR, f)
        if os.path.isfile(p):
            out.append({"name": f, "size": os.path.getsize(p),
                        "mtime": os.path.getmtime(p)})
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return jsonify({"ok": True, "files": out})


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


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"serving on http://127.0.0.1:{port}  (下载目录: {DL_DIR})")
    app.run(host="127.0.0.1", port=port, debug=False)
