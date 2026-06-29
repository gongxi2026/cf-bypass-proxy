const https = require('http');
const https_mod = require('https');

// ========== slowAES (Cloudflare 挑战破解) ==========
const slowAES = {aes:{keySize:{SIZE_128:16,SIZE_192:24,SIZE_256:32},sbox:[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22],rsbox:[82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125],rotate:function(i){for(var t=i[0],r=0;r<3;r++)i[r]=i[r+1];return i[3]=t,i},Rcon:[141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203],core:function(i,t){i=this.rotate(i);for(var r=0;r<4;++r)i[r]=this.sbox[i[r]];return i[0]=i[0]^this.Rcon[t],i},expandKey:function(i,t){for(var r=16*(this.numberOfRounds(t)+1),o=0,n=1,s=[],e=[],a=0;a<r;a++)e[a]=0;for(var h=0;h<t;h++)e[h]=i[h];for(o+=t;o<r;){for(var u=0;u<4;u++)s[u]=e[o-4+u];if(o%t==0&&(s=this.core(s,n++)),t==this.keySize.SIZE_256&&o%t==16)for(var f=0;f<4;f++)s[f]=this.sbox[s[f]];for(var l=0;l<4;l++)e[o]=e[o-t]^s[l],o++}return e},addRoundKey:function(i,t){for(var r=0;r<16;r++)i[r]^=t[r];return i},createRoundKey:function(i,t){for(var r=[],o=0;o<4;o++)for(var n=0;n<4;n++)r[4*n+o]=i[t+4*o+n];return r},subBytes:function(i,t){for(var r=0;r<16;r++)i[r]=(t?this.rsbox:this.sbox)[i[r]];return i},shiftRows:function(i,t){for(var r=0;r<4;r++)i=this.shiftRow(i,4*r,r,t);return i},shiftRow:function(i,t,r,o){for(var n=0;n<r;n++)if(o){for(var s=i[t+3],e=3;0<e;e--)i[t+e]=i[t+e-1];i[t]=s}else{for(s=i[t],e=0;e<3;e++)i[t+e]=i[t+e+1];i[t+3]=s}return i},galois_multiplication:function(i,t){for(var r=0,o=0;o<8;o++){1==(1&t)&&(r^=i),256<r&&(r^=256);var n=128&i;256<(i<<=1)&&(i^=256),128==n&&(i^=27),256<i&&(i^=256),256<(t>>=1)&&(t^=256)}return r},mixColumns:function(i,t){for(var r=[],o=0;o<4;o++){for(var n=0;n<4;n++)r[n]=i[4*n+o];r=this.mixColumn(r,t);for(var s=0;s<4;s++)i[4*s+o]=r[s]}return i},mixColumn:function(i,t){for(var r=[],r=t?[14,9,13,11]:[2,1,1,3],o=[],n=0;n<4;n++)o[n]=i[n];return i[0]=this.galois_multiplication(o[0],r[0])^this.galois_multiplication(o[3],r[1])^this.galois_multiplication(o[2],r[2])^this.galois_multiplication(o[1],r[3]),i[1]=this.galois_multiplication(o[1],r[0])^this.galois_multiplication(o[0],r[1])^this.galois_multiplication(o[3],r[2])^this.galois_multiplication(o[2],r[3]),i[2]=this.galois_multiplication(o[2],r[0])^this.galois_multiplication(o[1],r[1])^this.galois_multiplication(o[0],r[2])^this.galois_multiplication(o[3],r[3]),i[3]=this.galois_multiplication(o[3],r[0])^this.galois_multiplication(o[2],r[1])^this.galois_multiplication(o[1],r[2])^this.galois_multiplication(o[0],r[3]),i},round:function(i,t){return i=this.subBytes(i,!1),i=this.shiftRows(i,!1),i=this.mixColumns(i,!1),i=this.addRoundKey(i,t)},invRound:function(i,t){return i=this.shiftRows(i,!0),i=this.subBytes(i,!0),i=this.addRoundKey(i,t),i=this.mixColumns(i,!0)},main:function(i,t,r){i=this.addRoundKey(i,this.createRoundKey(t,0));for(var o=1;o<r;o++)i=this.round(i,this.createRoundKey(t,16*o));return i=this.subBytes(i,!1),i=this.shiftRows(i,!1),i=this.addRoundKey(i,this.createRoundKey(t,16*r))},invMain:function(i,t,r){i=this.addRoundKey(i,this.createRoundKey(t,16*r));for(var o=r-1;0<o;o--)i=this.invRound(i,this.createRoundKey(t,16*o));return i=this.shiftRows(i,!0),i=this.subBytes(i,!0),i=this.addRoundKey(i,this.createRoundKey(t,0))},numberOfRounds:function(i){var t;switch(i){case this.keySize.SIZE_128:t=10;break;case this.keySize.SIZE_192:t=12;break;case this.keySize.SIZE_256:t=14;break;default:return null}return t},encrypt:function(i,t,r){for(var o=[],n=[],s=this.numberOfRounds(r),e=0;e<4;e++)for(var a=0;a<4;a++)n[e+4*a]=i[4*e+a];for(var r=this.expandKey(t,r),n=this.main(n,r,s),h=0;h<4;h++)for(var u=0;u<4;u++)o[4*h+u]=n[h+4*u];return o},decrypt:function(i,t,r){for(var o=[],n=[],s=this.numberOfRounds(r),e=0;e<4;e++)for(var a=0;a<4;a++)n[e+4*a]=i[4*e+a];for(var r=this.expandKey(t,r),n=this.invMain(n,r,s),h=0;h<4;h++)for(var u=0;u<4;u++)o[4*h+u]=n[h+4*u];return o}},modeOfOperation:{OFB:0,CFB:1,CBC:2},getBlock:function(i,t,r,o){return 16<r-t&&(r=t+16),i.slice(t,r)},decrypt:function(t,r,o,n){var s=o.length;if(n.length%16)throw"iv length must be 128 bits.";var e,a=[],h=[],u=[],f=[],l=!0;if(null!==t){for(var c=0;c<Math.ceil(t.length/16);c++){var d=16*c,p=16*c+16;if(16*c+16>t.length&&(p=t.length),e=this.getBlock(t,d,p,r),r==this.modeOfOperation.CFB){for(l?(h=this.aes.encrypt(n,o,s),l=!1):h=this.aes.encrypt(a,o,s),i=0;i<16;i++)u[i]=h[i]^e[i];for(var v=0;v<p-d;v++)f.push(u[v]);a=e}else if(r==this.modeOfOperation.OFB){for(l?(h=this.aes.encrypt(n,o,s),l=!1):h=this.aes.encrypt(a,o,s),i=0;i<16;i++)u[i]=h[i]^e[i];for(v=0;v<p-d;v++)f.push(u[v]);a=h}else if(r==this.modeOfOperation.CBC){for(h=this.aes.decrypt(e,o,s),i=0;i<16;i++)u[i]=(l?n:a)[i]^h[i];l=!1;for(v=0;v<p-d;v++)f.push(u[v]);a=e}}r==this.modeOfOperation.CBC&&this.unpadBytesOut(f)}return f},padBytesIn:function(i){for(var t=16-i.length%16,r=0;r<t;r++)i.push(t)},unpadBytesOut:function(i){var t=0,r=-1;if(16<i.length){for(var o=i.length-1;o>=i.length-1-16&&i[o]<=16;o--){if(-1==r&&(r=i[o]),i[o]!=r){t=0;break}if(++t==r)break}0<t&&i.splice(i.length-t,t)}}};

function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}
function toHex(d){for(var e="",f=0;f<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}

function solveChallenge(html) {
  const match = html.match(/toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)/s);
  if (!match) return null;
  const a = toNumbers(match[1]);
  const b = toNumbers(match[2]);
  const c = toNumbers(match[3]);
  const result = slowAES.decrypt(c, 2, a, b);
  return toHex(result);
}

// ========== HTTP 服务器 ==========
const TARGET = 'https://gongxideruanjianku.42web.io';
const PORT = process.env.PORT || 3000;

function postWithRetry(path, postData, contentType, maxRetries) {
  return new Promise((resolve, reject) => {
    maxRetries = maxRetries || 3;
    let attempt = 0;
    
    function tryOnce() {
      attempt++;
      console.log(`  [尝试 ${attempt}] POST ${path}`);
      
      const url = new URL(TARGET);
      const options = {
        hostname: url.hostname,
        port: 443,
        path: path,
        method: 'POST',
        headers: {
          'Content-Type': contentType || 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData),
          'User-Agent': 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'zh-CN,zh;q=0.9'
        }
      };
      
      const req = https_mod.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          // 检查是否是挑战页
          if (body.includes('aes.js') || body.includes('slowAES')) {
            console.log(`  ⚠️ 遇到挑战页, 尝试破解...`);
            const cookieVal = solveChallenge(body);
            if (cookieVal && attempt < maxRetries) {
              console.log(`  🔑 破解成功: __test=${cookieVal}`);
              // 等待 1 秒后带 cookie 重试
              setTimeout(() => {
                options.headers['Cookie'] = `__test=${cookieVal}`;
                const req2 = https_mod.request(options, (res2) => {
                  let body2 = '';
                  res2.on('data', chunk => body2 += chunk);
                  res2.on('end', () => {
                    if (body2.includes('aes.js') || body2.includes('slowAES')) {
                      console.log(`  ❌ 重试后仍是挑战页`);
                      resolve({ status: 503, body: 'Cloudflare challenge persists' });
                    } else {
                      console.log(`  ✅ 绕过成功! Status: ${res2.statusCode}`);
                      resolve({ status: res2.statusCode, body: body2 });
                    }
                  });
                });
                req2.write(postData);
                req2.end();
              }, 1500);
            } else {
              console.log(`  ❌ 破解失败或超过重试次数`);
              resolve({ status: 503, body: 'Cloudflare challenge failed' });
            }
          } else {
            console.log(`  ✅ 直接成功! Status: ${res.statusCode}`);
            resolve({ status: res.statusCode, body: body });
          }
        });
      });
      
      req.on('error', (err) => {
        console.log(`  ❌ 网络错误: ${err.message}`);
        if (attempt < maxRetries) {
          console.log(`  ⏳ 1秒后重试...`);
          setTimeout(tryOnce, 1000);
        } else {
          reject(err);
        }
      });
      
      req.write(postData);
      req.end();
    }
    
    tryOnce();
  });
}

// 简单的 HTTP 服务器
const server = http.createServer(async (req, res) => {
  console.log(`\n📥 ${req.method} ${req.url}`);
  
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('OK');
    return;
  }
  
  // 收集请求体
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    const contentType = req.headers['content-type'] || 'application/x-www-form-urlencoded';
    
    try {
      const result = await postWithRetry(req.url, body, contentType);
      res.writeHead(result.status, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(result.body);
    } catch (err) {
      console.log(`  ❌ 最终失败: ${err.message}`);
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Proxy error: ' + err.message);
    }
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Cloudflare 挑战破解代理运行在端口 ${PORT}`);
  console.log(`   目标: ${TARGET}`);
  console.log(`   测试: curl -X POST http://localhost:${PORT}/mpayNotify -d "test=1"`);
});