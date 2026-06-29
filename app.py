"""
Cloudflare JS Challenge 绕过代理 - Python 版 (Hugging Face Space)
通过 subprocess 调用 Node.js 执行 slowAES 破解
"""
import subprocess
import re
import os
import json
import time
from flask import Flask, request, Response
import requests

app = Flask(__name__)

TARGET = "https://gongxideruanjianku.42web.io"
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

# 内嵌 slowAES 破解 JS (写入临时文件)
SLOWAES_JS = """function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}
function toHex(d){for(var e="",f=0;f<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}
var a=toNumbers(process.argv[2]),b=toNumbers(process.argv[3]),c=toNumbers(process.argv[4]);
var result=slowAES.decrypt(c,2,a,b);
console.log(toHex(result));"""

def solve_challenge(html):
    """从挑战页提取 a,b,c 并用 Node.js 破解"""
    match = re.search(r'toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)', html, re.DOTALL)
    if not match:
        return None
    
    a_hex, b_hex, c_hex = match.group(1), match.group(2), match.group(3)
    
    # 从源站获取 aes.js
    aes_js = ""
    try:
        r = requests.get(f"{TARGET}/aes.js", timeout=10, headers={"User-Agent": UA})
        aes_js = r.text
    except:
        # 使用缓存的 aes.js
        aes_path = os.path.join(os.path.dirname(__file__), "aes.js")
        if os.path.exists(aes_path):
            with open(aes_path) as f:
                aes_js = f.read()
    
    if not aes_js:
        return None
    
    # 拼接完整 JS 并执行
    full_js = aes_js + "\n" + SLOWAES_JS
    try:
        result = subprocess.run(
            ["node", "-e", full_js, a_hex, b_hex, c_hex],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"Node.js 执行失败: {e}")
        return None

def post_with_bypass(path, post_data, content_type, max_retries=3):
    """发送 POST 请求，自动处理 Cloudflare 挑战"""
    session = requests.Session()
    session.headers.update({
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9",
    })
    
    for attempt in range(max_retries):
        print(f"  [尝试 {attempt+1}] POST {path}")
        try:
            resp = session.post(
                f"{TARGET}{path}",
                data=post_data,
                headers={"Content-Type": content_type},
                timeout=20
            )
            body = resp.text
            
            if "aes.js" in body or "slowAES" in body:
                print(f"  ⚠️ 遇到挑战页, 破解中...")
                cookie_val = solve_challenge(body)
                if cookie_val:
                    print(f"  🔑 破解成功: __test={cookie_val}")
                    session.cookies.set("__test", cookie_val, domain="gongxideruanjianku.42web.io")
                    time.sleep(1.5)
                    continue
                else:
                    return 503, "Cloudflare challenge solve failed"
            else:
                print(f"  ✅ 成功! Status: {resp.status_code}")
                return resp.status_code, body
                
        except requests.exceptions.Timeout:
            print(f"  ⏱ 超时, 重试...")
            time.sleep(1)
        except Exception as e:
            print(f"  ❌ 错误: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)
    
    return 502, "All retries failed"

@app.route('/health')
def health():
    return "OK"

@app.route('/mpayNotify', methods=['POST'])
def proxy_notify():
    content_type = request.headers.get('Content-Type', 'application/x-www-form-urlencoded')
    post_data = request.form if request.form else request.get_data(as_text=True)
    
    if isinstance(post_data, dict):
        post_data = "&".join(f"{k}={v}" for k, v in post_data.items())
    
    status, body = post_with_bypass('/mpayNotify', post_data, content_type)
    return Response(body, status=status, content_type='text/html; charset=utf-8')

@app.route('/<path:path>', methods=['POST', 'GET'])
def proxy_any(path):
    content_type = request.headers.get('Content-Type', 'application/x-www-form-urlencoded')
    post_data = request.form if request.form else request.get_data(as_text=True)
    if isinstance(post_data, dict):
        post_data = "&".join(f"{k}={v}" for k, v in post_data.items())
    
    status, body = post_with_bypass(f"/{path}", post_data, content_type)
    return Response(body, status=status, content_type='text/html; charset=utf-8')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7860))
    app.run(host='0.0.0.0', port=port)