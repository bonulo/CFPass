export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' };
    if (method === 'OPTIONS') return new Response(null, { headers: corsHeaders });
    try {
      if (path === '/api/check' && method === 'GET') {
        const hasMaster = await env.PWD_KV.get('master');
        return j({ registered: !!hasMaster, hashPrefix: hasMaster ? hasMaster.substring(0, 8) + '...' : null }, 200, corsHeaders);
      }
      if (path === '/' && method === 'GET') return new Response(HTML, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders } });
      if (path === '/app.js' && method === 'GET') return new Response(CLIENT_JS, { headers: { 'Content-Type': 'application/javascript;charset=utf-8', ...corsHeaders } });
      if (path === '/api/register' && method === 'POST') return handleRegister(request, env, corsHeaders);
      if (path === '/api/login' && method === 'POST') return handleLogin(request, env, corsHeaders);
      if (path === '/api/passwords' && method === 'GET') return handleListPasswords(request, env, corsHeaders);
      if (path === '/api/passwords' && method === 'POST') return handleAddPassword(request, env, corsHeaders);
      if (path.match(/^\/api\/passwords\/[\w-]+$/) && method === 'PUT') return handleUpdatePassword(request, env, corsHeaders);
      if (path.match(/^\/api\/passwords\/[\w-]+$/) && method === 'DELETE') return handleDeletePassword(request, env, corsHeaders);
      return new Response('Not Found', { status: 404, headers: corsHeaders });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
    }
  },
};

function generateToken() {
  return crypto.randomUUID();
}

function hashMaster(pw) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw));
}

async function verifyAuth(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return await env.PWD_KV.get('session:' + auth.slice(7)) ? true : null;
}

async function handleRegister(request, env, ch) {
  const { masterPassword } = await request.json();
  if (!masterPassword || masterPassword.length < 8) return j({ error: 'At least 8 characters' }, 400, ch);
  if (await env.PWD_KV.get('master')) return j({ error: 'Already registered' }, 400, ch);
  const hash = btoa(String.fromCharCode(...new Uint8Array(await hashMaster(masterPassword))));
  await env.PWD_KV.put('master', hash);
  const token = generateToken();
  await env.PWD_KV.put('session:' + token, '1', { expirationTtl: 86400 });
  return j({ token }, 200, ch);
}

async function handleLogin(request, env, ch) {
  const { masterPassword } = await request.json();
  if (!masterPassword) return j({ error: 'Password required' }, 400, ch);
  const stored = await env.PWD_KV.get('master');
  if (!stored) return j({ error: 'No vault found' }, 400, ch);
  const hash = btoa(String.fromCharCode(...new Uint8Array(await hashMaster(masterPassword))));
  if (hash !== stored) return j({ error: 'Wrong password' }, 401, ch);
  const token = generateToken();
  await env.PWD_KV.put('session:' + token, '1', { expirationTtl: 86400 });
  return j({ token }, 200, ch);
}

async function handleListPasswords(request, env, ch) {
  if (!await verifyAuth(request, env)) return j({ error: 'Unauthorized' }, 401, ch);
  const list = await env.PWD_KV.list({ prefix: 'pwd:' });
  const items = [];
  for (const key of list.keys) {
    const v = await env.PWD_KV.get(key.name);
    if (v) items.push(JSON.parse(v));
  }
  return j(items, 200, ch);
}

async function handleAddPassword(request, env, ch) {
  if (!await verifyAuth(request, env)) return j({ error: 'Unauthorized' }, 401, ch);
  const { title, encryptedData } = await request.json();
  if (!title || !encryptedData) return j({ error: 'Title and data required' }, 400, ch);
  const id = crypto.randomUUID();
  const entry = { id, title, encryptedData, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  await env.PWD_KV.put('pwd:' + id, JSON.stringify(entry));
  return j(entry, 201, ch);
}

async function handleUpdatePassword(request, env, ch) {
  if (!await verifyAuth(request, env)) return j({ error: 'Unauthorized' }, 401, ch);
  const entryId = new URL(request.url).pathname.split('/').pop();
  const existing = await env.PWD_KV.get('pwd:' + entryId);
  if (!existing) return j({ error: 'Not found' }, 404, ch);
  const body = await request.json();
  const entry = JSON.parse(existing);
  if (body.title) entry.title = body.title;
  if (body.encryptedData) entry.encryptedData = body.encryptedData;
  entry.updatedAt = new Date().toISOString();
  await env.PWD_KV.put('pwd:' + entryId, JSON.stringify(entry));
  return j(entry, 200, ch);
}

async function handleDeletePassword(request, env, ch) {
  if (!await verifyAuth(request, env)) return j({ error: 'Unauthorized' }, 401, ch);
  const entryId = new URL(request.url).pathname.split('/').pop();
  if (!await env.PWD_KV.get('pwd:' + entryId)) return j({ error: 'Not found' }, 404, ch);
  await env.PWD_KV.delete('pwd:' + entryId);
  return j({ ok: true }, 200, ch);
}

function j(data, status, ch) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...ch } });
}

// ─── HTML ───
const HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CFPASS</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,'Segoe UI',system-ui,sans-serif;background:#f0f2f5;color:#303133;min-height:100vh}
.auth{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.auth-box{width:100%;max-width:400px;background:#fff;border:1px solid #dcdfe6;border-radius:12px;padding:44px 36px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.08)}
.auth-box h1{font-size:36px;font-weight:800;letter-spacing:-1px;margin-bottom:8px;color:#409eff}
.auth-box .sub{color:#909399;font-size:14px;margin-bottom:32px}
.field{margin-bottom:16px;text-align:left}
.field label{display:block;font-size:13px;font-weight:500;color:#606266;margin-bottom:6px}
.field input,.field textarea{width:100%;padding:10px 14px;background:#fff;border:1px solid #dcdfe6;border-radius:6px;color:#303133;font-size:14px;font-family:inherit;outline:none;transition:border .2s}
.field input:focus,.field textarea:focus{border-color:#409eff}
.field textarea{resize:vertical;min-height:60px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 20px;border:none;border-radius:6px;font-size:14px;font-weight:500;cursor:pointer;transition:all .15s;font-family:inherit}
.btn:active{transform:scale(.97)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-p{background:#409eff;color:#fff}.btn-p:hover{background:#66b1ff}
.btn-s{background:#fff;color:#606266;border:1px solid #dcdfe6}.btn-s:hover{background:#ecf5ff;color:#409eff;border-color:#c6e2ff}
.btn-d{color:#f56c6c;border:1px solid #f56c6c;background:transparent}.btn-d:hover{background:#f56c6c;color:#fff}
.btn-i{padding:6px 10px;background:#fff;color:#909399;border:1px solid #dcdfe6;border-radius:4px;font-size:12px}.btn-i:hover{color:#409eff;border-color:#c6e2ff}
.row{display:flex;gap:8px}
.main{display:none;min-height:100vh}.main.active{display:block}
.wrap{width:100%;max-width:1200px;margin:0 auto;padding:24px 32px}
.hdr{display:flex;align-items:center;justify-content:space-between;padding:16px 0 20px}
.hdr h2{font-size:22px;font-weight:700;color:#409eff}
.search{position:relative;margin-bottom:20px}
.search input{width:100%;padding:12px 14px 12px 40px;background:#fff;border:1px solid #dcdfe6;border-radius:6px;color:#303133;font-size:14px;outline:none}
.search input:focus{border-color:#409eff}
.search::before{content:'';position:absolute;left:14px;top:50%;transform:translateY(-50%);width:16px;height:16px;background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%23909399' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='M21 21l-4.35-4.35'/%3E%3C/svg%3E") no-repeat}
.add-form{background:#fff;border:1px solid #dcdfe6;border-radius:8px;padding:24px;margin-bottom:20px;display:none}
.add-form.open{display:block}
.add-form h3{font-size:16px;font-weight:600;color:#303133;margin-bottom:16px}
.form-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
.form-grid .full{grid-column:1/4}
.pw-field{position:relative}.pw-field input{padding-right:110px}
.pw-field .pw-acts{position:absolute;right:4px;top:50%;transform:translateY(-50%);display:flex;gap:3px}
.pw-field .pw-acts button{background:#f5f7fa;border:none;color:#909399;padding:4px 8px;border-radius:3px;font-size:11px;cursor:pointer;font-family:inherit;font-weight:500}
.pw-field .pw-acts button:hover{color:#409eff;background:#ecf5ff}
.pwd-header,.pwd-row{display:grid;grid-template-columns:1.2fr 1.5fr 1fr 180px 1.2fr 1fr 80px;align-items:center;gap:8px;padding:10px 16px}
.pwd-header{font-size:12px;font-weight:600;color:#909399;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #ebeef5}
.pwd-row{background:#fff;border:1px solid #ebeef5;border-radius:8px;transition:all .2s;margin-bottom:6px}
.pwd-row:hover{border-color:#c6e2ff;box-shadow:0 2px 8px rgba(64,158,255,.1)}
.c-cell{font-size:13px;color:#303133;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.c-url a{color:#409eff;text-decoration:none}.c-url a:hover{text-decoration:underline}
.c-pw{display:flex;align-items:center;gap:4px;white-space:nowrap}
.c-pw span{font-family:monospace;font-size:13px;color:#909399;min-width:80px}
.c-pw button{padding:4px 8px;font-size:11px}
.c-acts{display:flex;gap:4px;justify-content:flex-end}
.cp{cursor:pointer;padding:2px;border:none;background:none;color:#c0c4cc;font-size:12px;flex-shrink:0}.cp:hover{color:#409eff}
.c-acts .cp:last-child:hover{color:#f56c6c}
.empty{text-align:center;padding:60px 0;color:#909399}.empty p{font-size:14px;margin-top:12px}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);padding:12px 20px;background:#fff;border:1px solid #dcdfe6;border-radius:6px;font-size:13px;z-index:200;opacity:0;transition:opacity .3s;pointer-events:none;box-shadow:0 2px 12px rgba(0,0,0,.1)}
.toast.show{opacity:1}.toast.err{border-color:#f56c6c;color:#f56c6c}
.modal-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:300;align-items:flex-end;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:#fff;width:100%;max-width:500px;border-radius:16px 16px 0 0;padding:20px;max-height:80vh;overflow-y:auto;animation:slideUp .25s ease}
@keyframes slideUp{from{transform:translateY(100%)}to{transform:translateY(0)}}
.modal h3{font-size:18px;font-weight:700;color:#303133;margin-bottom:16px;padding-right:30px}
.modal-close{position:absolute;top:16px;right:16px;background:none;border:none;font-size:24px;color:#909399;cursor:pointer;padding:4px 8px}
.modal-field{margin-bottom:14px}
.modal-field .label{font-size:11px;font-weight:600;color:#909399;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.modal-field .value{font-size:14px;color:#303133;word-break:break-all;display:flex;align-items:center;gap:8px}
.modal-field .value a{color:#409eff;text-decoration:none}
.modal-field .value .copy-btn{background:none;border:none;color:#c0c4cc;cursor:pointer;padding:2px;flex-shrink:0}
.modal-field .value .copy-btn:hover{color:#409eff}
.modal-pw{display:flex;align-items:center;gap:6px}
.modal-pw span{font-family:monospace;font-size:14px;color:#303133}
.modal-pw button{background:#f5f7fa;border:none;color:#909399;padding:4px 8px;border-radius:4px;font-size:12px;cursor:pointer}
.modal-pw button:hover{color:#409eff;background:#ecf5ff}
.modal-actions{display:flex;gap:8px;margin-top:16px;padding-top:16px;border-top:1px solid #ebeef5}
.modal-actions .btn{flex:1}
@media(max-width:900px){.pwd-header{display:none}.pwd-row{grid-template-columns:1fr auto;gap:4px;padding:10px 12px;cursor:pointer}.pwd-row .c-cell:nth-child(n+3),.pwd-row .c-pw,.pwd-row .c-acts{display:none}.form-grid{grid-template-columns:1fr}.form-grid .full{grid-column:1}.wrap{padding:16px 12px}.hdr{flex-direction:column;align-items:flex-start;gap:12px}.row{flex-wrap:wrap;width:100%}.btn-s,.btn-i{font-size:13px;padding:8px 12px}}
</style>
</head>
<body>
<div class="auth" id="authScr">
<div class="auth-box">
<h1>CFPASS</h1>
<p class="sub">\u96f6\u77e5\u8bc6\u52a0\u5bc6\u5bc6\u7801\u7ba1\u7406\u5668</p>
<div class="field"><label>\u4e3b\u5bc6\u7801</label><input type="password" id="mpInput" placeholder="\u8bf7\u8f93\u5165\u4e3b\u5bc6\u7801" autocomplete="off"></div>
<button class="btn btn-p" style="width:100%;padding:14px" onclick="doAuth()">\u89e3\u9501</button>
</div>
</div>
<div class="main" id="mainScr">
<div class="wrap">
<div class="hdr">
<h2>CFPASS</h2>
<div class="row">
<button class="btn btn-s" onclick="toggleAdd()">+ \u6dfb\u52a0\u5bc6\u7801</button>
<button class="btn btn-s" onclick="exportCSV()">\u5bfc\u51fa</button>
<button class="btn btn-s" onclick="document.getElementById('importFile').click()">\u5bfc\u5165</button>
<input type="file" id="importFile" accept=".csv" style="display:none" onchange="importCSV(this)">
<button class="btn btn-i" onclick="lock()" title="\u9501\u5b9a"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></button>
</div>
</div>
<div class="add-form" id="addForm">
<h3 id="formTitle">\u6dfb\u52a0\u5bc6\u7801</h3>
<input type="hidden" id="editId">
<div class="form-grid">
<div class="field full"><label>\u6807\u9898 *</label><input id="fTitle" placeholder="\u4f8b\u5982 GitHub"></div>
<div class="field"><label>\u7528\u6237\u540d</label><input id="fUser" placeholder="\u7528\u6237\u540d"></div>
<div class="field"><label>\u7f51\u5740</label><input id="fUrl" placeholder="https://..."></div>
<div class="field"><label>\u90ae\u7bb1</label><input id="fEmail" type="email" placeholder="user@example.com"></div>
<div class="field"><label>\u5bc6\u7801 *</label><div class="pw-field"><input id="fPass" type="password" placeholder="\u5bc6\u7801"><div class="pw-acts"><button onclick="applySpec()">\u751f\u6210</button><button onclick="tog('fPass')">\u663e\u793a</button></div></div></div>
<div class="field" style="grid-column:span 2"><label>\u751f\u6210\u89c4\u5219 <span style="color:#909399;font-weight:400;font-size:12px">U=\u5927\u5199 W=\u5c0f\u5199 D=\u6570\u5b57 E=\u7279\u6b8a\u5b57\u7b26 M=- N=_</span></label><input id="fSpec" value="UWDDDDDDDD" style="font-family:monospace"></div>
<div class="field full"><label>\u5907\u6ce8</label><textarea id="fNotes" placeholder="\u53ef\u9009\u5907\u6ce8"></textarea></div>
</div>
<div style="text-align:right;margin-top:12px"><button class="btn btn-p" id="saveBtn" onclick="saveEntry()">\u4fdd\u5b58</button> <button class="btn btn-s" onclick="toggleAdd()">\u53d6\u6d88</button></div>
</div>
<div class="search"><input id="qInput" placeholder="\u641c\u7d22\u5bc6\u7801..." oninput="renderList()"></div>
<div class="pwd-list" id="pList"></div>
</div>
</div>
<div class="toast" id="toast"></div>
<div class="modal-overlay" id="modalOverlay" onclick="if(event.target===this)closeModal()">
<div class="modal" style="position:relative">
<button class="modal-close" onclick="closeModal()">&times;</button>
<h3 id="modalTitle"></h3>
<div class="modal-field"><div class="label">\u7f51\u5740</div><div class="value" id="modalUrl"></div></div>
<div class="modal-field"><div class="label">\u7528\u6237\u540d</div><div class="value" id="modalUser"></div></div>
<div class="modal-field"><div class="label">\u5bc6\u7801</div><div class="value modal-pw"><span id="modalPw">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</span><button onclick="toggleModalPw()">\u663e\u793a</button><button onclick="copyModalPw()">\u590d\u5236</button></div></div>
<div class="modal-field"><div class="label">\u90ae\u7bb1</div><div class="value" id="modalEmail"></div></div>
<div class="modal-field"><div class="label">\u5907\u6ce8</div><div class="value" id="modalNotes"></div></div>
<div class="modal-actions"><button class="btn btn-s" onclick="editFromModal()">\u7f16\u8f91</button><button class="btn btn-d" onclick="delFromModal()">\u5220\u9664</button></div>
</div>
</div>
<script src="/app.js"></script>
</body>
</html>`;

// ─── Client JS ───
const CLIENT_JS = `
var token=localStorage.getItem("pw_token");
var masterKey=null;
var entries=[];
var editingId=null;
var saving=false;
showAuth();

function showAuth(){document.getElementById("authScr").style.display="flex";document.getElementById("mainScr").classList.remove("active");document.getElementById("mpInput").value="";document.getElementById("mpInput").focus()}
function showMain(){document.getElementById("authScr").style.display="none";document.getElementById("mainScr").classList.add("active")}
function lock(){token=null;masterKey=null;entries=[];localStorage.removeItem("pw_token");showAuth()}
function tog(id){var el=document.getElementById(id);el.type=el.type==="password"?"text":"password"}
function cpText(b,t){navigator.clipboard.writeText(t);toast("\\u5df2\\u590d\\u5236")}
function esc(s){var d=document.createElement("div");d.textContent=s||"";return d.innerHTML}
function toast(m,err){var el=document.getElementById("toast");el.textContent=m;el.className="toast show"+(err?" err":"");setTimeout(function(){el.className="toast"},2200)}

async function api(path,opts){
  opts=opts||{};var h={"Content-Type":"application/json"};
  if(token)h["Authorization"]="Bearer "+token;
  var r=await fetch(path,Object.assign({},opts,{headers:Object.assign({},h,opts.headers||{})}));
  return{ok:r.ok,status:r.status,data:await r.json()};
}
async function deriveKey(pw){
  var enc=new TextEncoder();
  var km=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:enc.encode("PWDM-SALT-v1"),iterations:200000,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
function buf(a){return btoa(String.fromCharCode.apply(null,a))}
function unbuf(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})}
async function encrypt(plain){var iv=crypto.getRandomValues(new Uint8Array(12));var enc=new TextEncoder();var ct=await crypto.subtle.encrypt({name:"AES-GCM",iv:iv},masterKey,enc.encode(plain));return{iv:buf(iv),d:buf(new Uint8Array(ct))}}
async function decrypt(blob){var iv=unbuf(blob.iv);var d=unbuf(blob.d);var pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:iv},masterKey,d);return new TextDecoder().decode(pt)}

async function doAuth(){
  var pw=document.getElementById("mpInput").value;
  if(!pw){toast("\\u8bf7\\u8f93\\u5165\\u4e3b\\u5bc6\\u7801",true);return}
  try{masterKey=await deriveKey(pw)}catch(e){toast("\\u5bc6\\u94a5\\u751f\\u6210\\u5931\\u8d25",true);return}
  if(!masterKey){toast("\\u5bc6\\u94a5\\u751f\\u6210\\u5931\\u8d25",true);return}
  var r=await api("/api/login",{method:"POST",body:JSON.stringify({masterPassword:pw})});
  if(r.status===401){toast("\\u5bc6\\u7801\\u9519\\u8bef",true);masterKey=null;return}
  if(r.status===400&&r.data.error&&r.data.error.indexOf("No vault")!==-1){
    if(pw.length<8){toast("\\u5bc6\\u7801\\u81f3\\u5c118\\u4f4d",true);masterKey=null;return}
    r=await api("/api/register",{method:"POST",body:JSON.stringify({masterPassword:pw})});
    if(!r.ok){toast(r.data.error,true);masterKey=null;return}
  }else if(!r.ok){toast(r.data.error||"\\u5931\\u8d25",true);masterKey=null;return}
  token=r.data.token;localStorage.setItem("pw_token",token);showMain();await loadEntries();
}

async function loadEntries(){
  var r=await api("/api/passwords");
  if(!r.ok){toast("\\u52a0\\u8f7d\\u5931\\u8d25",true);return}
  var raw=r.data||[];var arr=[];
  for(var i=0;i<raw.length;i++){var e=raw[i];var item={id:e.id,title:e.title,createdAt:e.createdAt,updatedAt:e.updatedAt};
    try{var blob=JSON.parse(e.encryptedData);var plain=JSON.parse(await decrypt(blob));
      item.url=plain.url||"";item.username=plain.username||"";item.password=plain.password||"";item.email=plain.email||"";item.notes=plain.notes||""
    }catch(err){item.url="";item.username="";item.password="";item.email="";item.notes=""}
    arr.push(item);
  }
  entries=arr;
  renderList();
}

function renderList(){
  var q=document.getElementById("qInput").value.toLowerCase();
  var filtered=entries.filter(function(e){return(e.title||"").toLowerCase().indexOf(q)!==-1||(e.url||"").toLowerCase().indexOf(q)!==-1||(e.username||"").toLowerCase().indexOf(q)!==-1||(e.email||"").toLowerCase().indexOf(q)!==-1});
  var el=document.getElementById("pList");
  if(!filtered.length){el.innerHTML='<div class="empty"><p>'+(entries.length?"\\u6ca1\\u6709\\u5339\\u914d":"\\u6682\\u65e0\\u5bc6\\u7801\\uff0c\\u70b9\\u51fb\\u6dfb\\u52a0!")+'</p></div>';return}
  var svgC='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
  var svgE='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  var svgD='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>';
  var svgEd='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  var hdr='<div class="pwd-header"><span>\\u6807\\u9898</span><span>\\u7f51\\u7ad9</span><span>\\u7528\\u6237\\u540d</span><span>\\u5bc6\\u7801</span><span>\\u90ae\\u7bb1</span><span>\\u5907\\u6ce8</span><span>\\u64cd\\u4f5c</span></div>';
  var rows="";
  for(var i=0;i<filtered.length;i++){
    var e=filtered[i];var url=e.url||"";var pw=e.password||"";
    rows+='<div class="pwd-row" onclick="openModal(\\''+e.id+'\\')">';
    rows+='<div class="c-cell"><span title="'+esc(e.title)+'">'+esc(e.title||"\\u2014")+'</span>'+cpB(e.title)+'</div>';
    rows+='<div class="c-cell c-url">'+(url?'<a href="'+esc(url)+'" target="_blank" title="'+esc(url)+'">'+esc(url)+'</a>'+cpB(url):"\\u2014")+'</div>';
    rows+='<div class="c-cell"><span title="'+esc(e.username)+'">'+esc(e.username||"\\u2014")+'</span>'+cpB(e.username)+'</div>';
    rows+='<div class="c-pw"><span id="pw_'+e.id+'">'+esc(pw||"\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022")+'</span>';
    rows+='<button class="cp" onclick="togglePw(\\''+e.id+'\\')" title="\\u663e\\u793a">'+svgE+'</button>';
    rows+='<button class="cp" onclick="copyPw(\\''+e.id+'\\')" title="\\u590d\\u5236">'+svgC+'</button></div>';
    rows+='<div class="c-cell"><span title="'+esc(e.email)+'">'+esc(e.email||"\\u2014")+'</span>'+cpB(e.email)+'</div>';
    rows+='<div class="c-cell"><span title="'+esc(e.notes)+'">'+esc(e.notes||"\\u2014")+'</span>'+cpB(e.notes)+'</div>';
    rows+='<div class="c-acts"><button class="cp" onclick="editEntry(\\''+e.id+'\\')" title="\\u7f16\\u8f91">'+svgEd+'</button>';
    rows+='<button class="cp" onclick="delEntry(\\''+e.id+'\\')" title="\\u5220\\u9664">'+svgD+'</button></div></div>';
  }
  el.innerHTML=hdr+rows;
}

function cpB(v){
  if(!v)return"";
  return '<button class="cp" onclick="cpText(this,\\''+esc(v).replace(/'/g,"\\'")+'\\')" title="\\u590d\\u5236"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>';
}

function togglePw(id){
  var el=document.getElementById("pw_"+id);var e=entries.find(function(x){return x.id===id});if(!e)return;
  if(el.dataset.shown==="1"){el.textContent="\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022";el.dataset.shown="0"}
  else{el.textContent=e.password||"(\\u7a7a)";el.dataset.shown="1"}
}
function copyPw(id){var e=entries.find(function(x){return x.id===id});if(e&&e.password){navigator.clipboard.writeText(e.password);toast("\\u5df2\\u590d\\u5236")}}

function toggleAdd(){
  var form=document.getElementById("addForm");
  if(form.classList.contains("open")){form.classList.remove("open");editingId=null}
  else{form.classList.add("open");document.getElementById("formTitle").textContent="\\u6dfb\\u52a0\\u5bc6\\u7801";editingId=null;
    ["fTitle","fUrl","fUser","fEmail","fPass","fNotes"].forEach(function(id){document.getElementById(id).value=""});
    document.getElementById("fPass").placeholder="\\u5bc6\\u7801";document.getElementById("fTitle").focus();}
}

function editEntry(id){
  var e=entries.find(function(x){return x.id===id});if(!e)return;editingId=id;
  document.getElementById("formTitle").textContent="\\u7f16\\u8f91\\u5bc6\\u7801";
  document.getElementById("fTitle").value=e.title;document.getElementById("fUrl").value=e.url;
  document.getElementById("fUser").value=e.username;document.getElementById("fEmail").value=e.email;
  document.getElementById("fPass").value="";document.getElementById("fPass").placeholder="\\u7559\\u7a7a\\u4fdd\\u6301\\u4e0d\\u53d8";
  document.getElementById("fNotes").value=e.notes;
  document.getElementById("addForm").classList.add("open");document.getElementById("fTitle").focus();
  window.scrollTo({top:0,behavior:"smooth"});
}

async function saveEntry(){
  if(saving)return;
  if(!masterKey){toast("\\u8bf7\\u5148\\u8f93\\u5165\\u4e3b\\u5bc6\\u7801\\u89e3\\u9501",true);return}
  var title=document.getElementById("fTitle").value.trim();
  var pw=document.getElementById("fPass").value;
  if(!title){toast("\\u8bf7\\u8f93\\u5165\\u6807\\u9898",true);return}
  if(!editingId&&!pw){toast("\\u8bf7\\u8f93\\u5165\\u5bc6\\u7801",true);return}
  var url=document.getElementById("fUrl").value.trim();
  var username=document.getElementById("fUser").value.trim();
  var email=document.getElementById("fEmail").value.trim();
  var notes=document.getElementById("fNotes").value.trim();
  var eid=editingId;
  var existing=null;
  if(eid)existing=entries.find(function(x){return x.id===eid});
  var plain={url:url||(existing?existing.url:""),username:username||(existing?existing.username:""),password:pw||(existing?existing.password:""),email:email||(existing?existing.email:""),notes:notes||(existing?existing.notes:"")};
  var data={title:title};
  try{var blob=await encrypt(JSON.stringify(plain));data.encryptedData=JSON.stringify(blob)}
  catch(e){toast("\\u52a0\\u5bc6\\u5931\\u8d25",true);return}
  saving=true;
  var btn=document.getElementById("saveBtn");if(btn)btn.disabled=true;
  var tmpId=eid||("tmp_"+Date.now()+"_"+Math.random().toString(36).slice(2,6));
  if(!eid){
    entries.push({id:tmpId,title:title,url:url,username:username,password:pw,email:email,notes:notes,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()});
  }else{
    for(var i=0;i<entries.length;i++){if(entries[i].id===eid){entries[i].title=title;entries[i].url=url;entries[i].username=username;entries[i].email=email;entries[i].notes=notes;if(pw)entries[i].password=pw;break;}}
  }
  toggleAdd();renderList();
  try{
    var r=eid?await api("/api/passwords/"+eid,{method:"PUT",body:JSON.stringify(data)}):await api("/api/passwords",{method:"POST",body:JSON.stringify(data)});
    if(r.ok){
      var saved=r.data;
      if(!eid){
        for(var i=0;i<entries.length;i++){if(entries[i].id===tmpId){entries[i].id=saved.id;entries[i].createdAt=saved.createdAt;entries[i].updatedAt=saved.updatedAt;break;}}
        renderList();
      }
      toast(eid?"\\u5df2\\u66f4\\u65b0":"\\u5df2\\u6dfb\\u52a0");
    }else{
      if(!eid){for(var i=0;i<entries.length;i++){if(entries[i].id===tmpId){entries.splice(i,1);break;}}renderList();}
      else{try{await loadEntries();}catch(x){}}
      toast(r.data.error||"\\u64cd\\u4f5c\\u5931\\u8d25",true);
    }
  }catch(e){
    if(!eid){for(var i=0;i<entries.length;i++){if(entries[i].id===tmpId){entries.splice(i,1);break;}}renderList();}
    else{try{await loadEntries();}catch(x){}}
    toast("\\u8bf7\\u6c42\\u5931\\u8d25",true);
  }
  saving=false;if(btn)btn.disabled=false;
}

async function delEntry(id){
  if(!confirm("\\u786e\\u5b9a\\u5220\\u9664?"))return;
  var r=await api("/api/passwords/"+id,{method:"DELETE"});
  if(r.ok){await loadEntries();toast("\\u5df2\\u5220\\u9664")}
}

async function applySpec(){
  var spec=document.getElementById("fSpec").value;
  if(!spec){toast("\\u8bf7\\u8f93\\u5165\\u751f\\u6210\\u89c4\\u5219",true);return}
  var map={U:"ABCDEFGHIJKLMNOPQRSTUVWXYZ",W:"abcdefghijklmnopqrstuvwxyz",D:"0123456789",E:"!@#$%^&*()=+[]{}|;:,.<>?",M:"-",N:"_"};
  var pw="";for(var i=0;i<spec.length;i++){var pool=map[spec[i].toUpperCase()];if(pool){var arr=crypto.getRandomValues(new Uint8Array(1));pw+=pool[arr[0]%pool.length]}else{pw+=spec[i]}}
  if(!pw){toast("\\u89c4\\u5219\\u65e0\\u6548",true);return}
  document.getElementById("fPass").value=pw;document.getElementById("fPass").type="text";
  toast("\\u5df2\\u751f\\u6210 "+pw.length+" \\u4f4d\\u5bc6\\u7801");
}

async function exportCSV(){
  if(!entries.length){toast("\\u6ca1\\u6709\\u6570\\u636e\\u53ef\\u5bfc\\u51fa",true);return}
  var csv="\\u6807\\u9898,\\u7f51\\u7ad9,\\u7528\\u6237\\u540d,\\u5bc6\\u7801,\\u5907\\u6ce8,\\n";
  for(var i=0;i<entries.length;i++){var e=entries[i];csv+=[e.title,e.url,e.username,e.password,e.email,e.notes].map(function(v){return '\\"'+(v||"").replace(/"/g,'""')+'\\"'}).join(",")+"\\n"}
  var blob=new Blob([csv],{type:"text/csv;charset=utf-8"});
  var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="PWDM_"+new Date().toISOString().slice(0,10)+".csv";a.click();URL.revokeObjectURL(a.href);toast("\\u5bfc\\u51fa\\u6210\\u529f");
}

async function importCSV(input){
  var file=input.files[0];if(!file)return;
  var text=await file.text();var raw=await file.arrayBuffer();var bytes=new Uint8Array(raw);
  if(bytes[0]===0xFF&&bytes[1]===0xFE){text=new TextDecoder("utf-16le").decode(bytes)}
  else if(bytes[0]===0xFE&&bytes[1]===0xFF){text=new TextDecoder("utf-16be").decode(bytes)}
  else{var utf8=new TextDecoder("utf-8",{fatal:false}).decode(bytes);if((utf8.match(/\\uFFFD/g)||[]).length>2)text=new TextDecoder("gbk").decode(bytes)}
  var lines=text.split("\\n").filter(function(l){return l.trim()});
  if(lines.length<2){toast("CSV \\u4e3a\\u7a7a",true);return}
  var header=lines[0].toLowerCase().replace(/"/g,"");
  var hasHeader=header.indexOf("titel")!==-1||header.indexOf("account")!==-1||header.indexOf("title")!==-1||header.indexOf("\\u6807\\u9898")!==-1;
  var start=hasHeader?1:0;var created=0,updated=0;
  input.value="";
  var form=document.getElementById("addForm");
  if(form.classList.contains("open"))form.classList.remove("open");
  for(var i=start;i<lines.length;i++){
    var cols=parseCSVLine(lines[i]);if(!cols.length)continue;
    var title=cols[0]||"";var plain={url:cols[1]||"",username:cols[2]||"",password:cols[3]||"",email:cols[4]||"",notes:cols[5]||""};
    if(!title&&!plain.password)continue;
    var data;try{var blob=await encrypt(JSON.stringify(plain));data={title:title,encryptedData:JSON.stringify(blob)}}catch(err){continue}
    var existing=entries.find(function(e){return e.title===title&&e.username===plain.username});
    if(existing){
      var r=await api("/api/passwords/"+existing.id,{method:"PUT",body:JSON.stringify(data)});
      if(r.ok){existing.url=plain.url;existing.username=plain.username;existing.password=plain.password;existing.email=plain.email;existing.notes=plain.notes;updated++;renderList();}
    }else{
      var r2=await api("/api/passwords",{method:"POST",body:JSON.stringify(data)});
      if(r2.ok){entries.push({id:r2.data.id,title:title,url:plain.url,username:plain.username,password:plain.password,email:plain.email,notes:plain.notes,createdAt:r2.data.createdAt,updatedAt:r2.data.updatedAt});created++;renderList();}
    }
  }
  document.getElementById("pList").scrollIntoView({behavior:"smooth"});
  toast("\\u5bfc\\u5165\\u5b8c\\u6210\\uff0c\\u65b0\\u589e "+created+" \\u6761\\uff0c\\u66f4\\u65b0 "+updated+" \\u6761");
}

function parseCSVLine(line){
  var result=[],current="",inQuotes=false;
  for(var i=0;i<line.length;i++){var c=line[i];
    if(inQuotes){if(c==='"'){if(i+1<line.length&&line[i+1]==='"'){current+='"';i++}else inQuotes=false}else{current+=c}}
    else{if(c==='"')inQuotes=true;else if(c===","){result.push(current);current=""}else current+=c}}
  result.push(current);return result;
}

document.getElementById("mpInput").addEventListener("keydown",function(e){if(e.key==="Enter")doAuth()});

var modalEntry=null;var modalPwShown=false;
function openModal(id){
  var e=entries.find(function(x){return x.id===id});if(!e)return;
  modalEntry=e;modalPwShown=false;
  document.getElementById("modalTitle").textContent=e.title||"\\u2014";
  document.getElementById("modalUrl").innerHTML=e.url?'<a href="'+esc(e.url)+'" target="_blank">'+esc(e.url)+'</a>'+cpBtn(e.url):'<span style="color:#909399">\\u2014</span>';
  document.getElementById("modalUser").innerHTML=(e.username?esc(e.username)+' '+cpBtn(e.username):'<span style="color:#909399">\\u2014</span>');
  document.getElementById("modalPw").textContent="\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022";
  document.getElementById("modalEmail").innerHTML=(e.email?esc(e.email)+' '+cpBtn(e.email):'<span style="color:#909399">\\u2014</span>');
  document.getElementById("modalNotes").innerHTML=(e.notes?esc(e.notes)+' '+cpBtn(e.notes):'<span style="color:#909399">\\u2014</span>');
  document.getElementById("modalOverlay").classList.add("show");
}
function closeModal(){document.getElementById("modalOverlay").classList.remove("show");modalEntry=null}
function toggleModalPw(){
  if(!modalEntry)return;
  var el=document.getElementById("modalPw");
  modalPwShown=!modalPwShown;
  el.textContent=modalPwShown?(modalEntry.password||"(\\u7a7a)"):"\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022";
  el.nextElementSibling.textContent=modalPwShown?"\\u9690\\u85cf":"\\u663e\\u793a";
}
function copyModalPw(){if(modalEntry&&modalEntry.password){navigator.clipboard.writeText(modalEntry.password);toast("\\u5df2\\u590d\\u5236")}}
function editFromModal(){if(modalEntry){closeModal();editEntry(modalEntry.id)}}
async function delFromModal(){if(!modalEntry)return;if(!confirm("\\u786e\\u5b9a\\u5220\\u9664?"))return;var id=modalEntry.id;closeModal();var r=await api("/api/passwords/"+id,{method:"DELETE"});if(r.ok){await loadEntries();toast("\\u5df2\\u5220\\u9664")}}
function cpBtn(v){if(!v)return"";return '<button class="copy-btn" onclick="navigator.clipboard.writeText(this.getAttribute(\\"data-v\\"));toast(\\"\\u5df2\\u590d\\u5236\\")" data-v="'+esc(v).replace(/"/g,"&quot;")+'" title="\\u590d\\u5236"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>'}
`;
