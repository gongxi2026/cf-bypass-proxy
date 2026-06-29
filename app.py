"""
Cloudflare JS Challenge 绕过代理 - 纯 Python 版 (Hugging Face Space)
内置 slowAES 解密，无需 Node.js，无需任何外部依赖（除 flask, requests）
"""
import os, re, time
from flask import Flask, request, Response
import requests

app = Flask(__name__)
TARGET = "https://gongxideruanjianku.42web.io"
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

# ========== 纯 Python slowAES (AES-128-CBC, 与 Cloudflare aes.js 兼容) ==========
class SlowAES:
    sbox = [99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22]
    rsbox = [82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125]
    Rcon = [141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203]

    @classmethod
    def _nr(cls, size):
        return {16: 10, 24: 12, 32: 14}[size]

    @classmethod
    def _expandKey(cls, key, size):
        nk = size // 4
        nr = cls._nr(size)
        w = [0] * ((nr + 1) * 16)
        for i in range(nk * 4):
            w[i] = key[i]
        for i in range(nk, (nr + 1) * 4):
            b = i * 4
            t0, t1, t2, t3 = w[b-4], w[b-3], w[b-2], w[b-1]
            if i % nk == 0:
                t0, t1, t2, t3 = cls.sbox[t1], cls.sbox[t2], cls.sbox[t3], cls.sbox[t0]
                t0 ^= cls.Rcon[i // nk]
            elif nk > 6 and i % nk == 4:
                t0, t1, t2, t3 = cls.sbox[t0], cls.sbox[t1], cls.sbox[t2], cls.sbox[t3]
            w[b] = w[(i-nk)*4] ^ t0
            w[b+1] = w[(i-nk)*4+1] ^ t1
            w[b+2] = w[(i-nk)*4+2] ^ t2
            w[b+3] = w[(i-nk)*4+3] ^ t3
        return w

    @classmethod
    def _gmul(cls, a, b):
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi: a ^= 0x1B
            b >>= 1
        return p

    @classmethod
    def _invMixCol(cls, s):
        c = [s[0], s[1], s[2], s[3]]
        s[0] = cls._gmul(c[0],14) ^ cls._gmul(c[1],11) ^ cls._gmul(c[2],13) ^ cls._gmul(c[3],9)
        s[1] = cls._gmul(c[0],9) ^ cls._gmul(c[1],14) ^ cls._gmul(c[2],11) ^ cls._gmul(c[3],13)
        s[2] = cls._gmul(c[0],13) ^ cls._gmul(c[1],9) ^ cls._gmul(c[2],14) ^ cls._gmul(c[3],11)
        s[3] = cls._gmul(c[0],11) ^ cls._gmul(c[1],13) ^ cls._gmul(c[2],9) ^ cls._gmul(c[3],14)

    @classmethod
    def _invShiftRow(cls, s):
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]

    @classmethod
    def decrypt_cbc(cls, ct, key, iv):
        """AES-128-CBC 解密，兼容 Cloudflare slowAES.decrypt(c, 2, a, b)"""
        size = len(key)
        nr = cls._nr(size)
        w = cls._expandKey(key, size)
        pt = []
        prev = list(iv)
        for i in range(0, len(ct), 16):
            block = ct[i:i+16]
            state = block[:]
            # AddRoundKey (last round key)
            for j in range(16):
                state[j] ^= w[nr*16 + j]
            # Main rounds
            for rnd in range(nr-1, 0, -1):
                cls._invShiftRow(state)
                for j in range(16):
                    state[j] = cls.rsbox[state[j]]
                for j in range(16):
                    state[j] ^= w[rnd*16 + j]
                for c in range(4):
                    cls._invMixCol(state[c*4:c*4+4])
            # Final round
            cls._invShiftRow(state)
            for j in range(16):
                state[j] = cls.rsbox[state[j]]
            for j in range(16):
                state[j] ^= w[j]
            # XOR with previous block
            for j in range(16):
                pt.append(state[j] ^ prev[j])
            prev = block
        # PKCS7 unpadding
        if pt:
            pad = pt[-1]
            if 1 <= pad <= 16:
                pt = pt[:-pad]
        return pt

def _to_nums(s):
    return [int(s[i:i+2], 16) for i in range(0, len(s), 2)]

def _to_hex(b):
    return ''.join(f'{x:02x}' for x in b)

def solve_challenge(html):
    m = re.search(r'toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)', html, re.DOTALL)
    if not m:
        return None
    try:
        a, b, c = _to_nums(m.group(1)), _to_nums(m.group(2)), _to_nums(m.group(3))
        return _to_hex(SlowAES.decrypt_cbc(c, a, b))
    except Exception as e:
        print(f"  ❌ AES 解密失败: {e}")
        return None

def post_with_bypass(path, data, ct, retries=3):
    sess = requests.Session()
    sess.headers.update({"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.9"})
    for i in range(retries):
        print(f"  [尝试 {i+1}] POST {path}")
        try:
            resp = sess.post(f"{TARGET}{path}", data=data, headers={"Content-Type": ct}, timeout=20)
            body = resp.text
            if "aes.js" in body or "slowAES" in body:
                print(f"  ⚠️ 挑战页, 破解中...")
                cv = solve_challenge(body)
                if cv:
                    print(f"  🔑 __test={cv}")
                    sess.cookies.set("__test", cv, domain="gongxideruanjianku.42web.io")
                    time.sleep(1.5)
                    continue
                return 503, "CF challenge solve failed"
            print(f"  ✅ Status: {resp.status_code}")
            return resp.status_code, body
        except requests.exceptions.Timeout:
            print(f"  ⏱ 超时")
            time.sleep(1)
        except Exception as e:
            print(f"  ❌ {e}")
            if i < retries - 1: time.sleep(1)
    return 502, "All retries failed"

@app.route('/health')
def health():
    return "OK"

@app.route('/mpayNotify', methods=['POST'])
def proxy_notify():
    ct = request.headers.get('Content-Type', 'application/x-www-form-urlencoded')
    data = request.form if request.form else request.get_data(as_text=True)
    status, body = post_with_bypass('/mpayNotify', data, ct)
    return Response(body, status=status, content_type='text/html; charset=utf-8')

@app.route('/<path:path>', methods=['POST', 'GET'])
def proxy_any(path):
    ct = request.headers.get('Content-Type', 'application/x-www-form-urlencoded')
    data = request.form if request.form else request.get_data(as_text=True)
    status, body = post_with_bypass(f"/{path}", data, ct)
    return Response(body, status=status, content_type='text/html; charset=utf-8')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 7860)))
