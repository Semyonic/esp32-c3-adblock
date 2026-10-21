#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).
// Glass Aurora theme: client cards with names (manual label > mDNS > IP),
// editable via /label, live rate, block-ratio donut. Self-contained, ~15 KB.

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<meta name=theme-color content=#0a0e1a><title>C3 AdBlock</title><style>
*{box-sizing:border-box}body{font:14px/1.5 system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;background:#0a0e1a;color:#e7ecf5}
body:before{content:'';position:fixed;inset:0;background:radial-gradient(600px 400px at 15% 0%,rgba(52,211,153,.16),transparent 60%),radial-gradient(700px 500px at 90% 10%,rgba(56,130,246,.14),transparent 60%),radial-gradient(500px 500px at 60% 100%,rgba(167,139,250,.12),transparent 60%);pointer-events:none}
.glass{background:rgba(255,255,255,.05);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,.1);border-radius:20px}
.wrap{max-width:1060px;margin:auto;padding:20px 16px 40px;position:relative}
header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.logo{width:46px;height:46px;border-radius:15px;background:linear-gradient(135deg,#34d399,#22d3ee);display:grid;place-items:center;font-size:22px;box-shadow:0 0 30px rgba(52,211,153,.35)}
h1{margin:0;font-size:19px}h1 small{display:block;font-weight:400;color:#94a3b8;font-size:12px}
.pill{border-radius:99px;padding:5px 14px;font-size:12.5px;font-weight:600;background:rgba(52,211,153,.14);color:#6ee7b7;border:1px solid rgba(52,211,153,.3);display:inline-flex;align-items:center;gap:7px}
.pill.off{background:rgba(251,191,36,.13);color:#fcd34d;border-color:rgba(251,191,36,.35)}
.dot{width:7px;height:7px;border-radius:50%;background:#34d399;animation:p 1.6s infinite}@keyframes p{50%{opacity:.3}}
header .sp{flex:1}
button{background:rgba(255,255,255,.07);color:#e7ecf5;border:1px solid rgba(255,255,255,.14);border-radius:12px;padding:8px 16px;cursor:pointer;font-size:13px;transition:.15s}
button:hover{background:rgba(255,255,255,.14);transform:translateY(-1px)}
.grad{background:linear-gradient(135deg,#34d399,#22d3ee);color:#06281f;border:none;font-weight:700}.grad:hover{box-shadow:0 4px 20px rgba(52,211,153,.35)}
select,input{background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.14);color:#e7ecf5;border-radius:11px;padding:8px 10px;font-size:13px}
.hero{display:grid;grid-template-columns:300px 1fr;gap:16px;margin-bottom:16px}@media(max-width:820px){.hero{grid-template-columns:1fr}}
.hpad{padding:18px 20px}
.big{font-size:30px;font-weight:800;background:linear-gradient(135deg,#6ee7b7,#67e8f9);-webkit-background-clip:text;background-clip:text;color:transparent}
.lab{color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.8px}
.donut{display:flex;align-items:center;gap:18px}
.legend div{margin:5px 0;font-size:13px}.legend i{width:10px;height:10px;border-radius:99px;display:inline-block;margin-right:8px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.kpi{padding:14px 16px}.kpi .v{font-size:22px;font-weight:700;margin-top:2px}
.up{border:1.5px dashed rgba(255,255,255,.2);border-radius:16px;padding:16px;text-align:center;color:#94a3b8;font-size:13px;margin-top:10px;cursor:pointer;display:block}
.up:hover{border-color:rgba(52,211,153,.5);color:#e7ecf5}.up b{color:#e7ecf5}
h2{font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:.8px;margin:22px 0 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.cl{padding:14px 16px;transition:.15s}.cl:hover{border-color:rgba(52,211,153,.4);transform:translateY(-2px)}
.cl.bz{border-color:rgba(248,113,113,.45)}
.cl .top{display:flex;align-items:center;gap:10px}
.av{width:36px;height:36px;border-radius:12px;display:grid;place-items:center;font-size:15px;font-weight:700;color:#06281f;background:linear-gradient(135deg,#6ee7b7,#67e8f9);flex:none}
.cl.bz .av{background:linear-gradient(135deg,#fca5a5,#fbbf24)}
.cl .nm{font-weight:600;word-break:break-all}
.cl .sub{color:#94a3b8;font-size:11.5px;font-family:ui-monospace,Menlo,monospace}
.bar{height:7px;background:rgba(255,255,255,.08);border-radius:99px;margin:11px 0 8px;overflow:hidden}
.bar i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,#f87171,#fbbf24);transition:width .6s}
.cl .nums{display:flex;gap:14px;font-size:12px;align-items:center}
.cl .nums b{font-size:14px}
.bred{color:#fca5a5}.agrn{color:#6ee7b7}
.ban{margin-left:auto;padding:4px 11px;font-size:12px;color:#fca5a5;border-color:rgba(248,113,113,.4);background:rgba(248,113,113,.08)}
.ban.unb{color:#6ee7b7;border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.08)}
.pen{background:none;border:none;color:#94a3b8;cursor:pointer;font-size:13px;padding:0 2px}.pen:hover{color:#67e8f9}
.tg{font-size:10px;border-radius:5px;padding:1px 6px;font-style:normal;vertical-align:1px}
.tg.m{color:#6ee7b7;border:1px solid rgba(52,211,153,.4)}.tg.a{color:#94a3b8;border:1px solid rgba(255,255,255,.2)}
.chip{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:99px;padding:6px 8px 6px 15px;font-size:13px;display:inline-flex;gap:9px;align-items:center;margin:0 8px 8px 0}
.chip button{background:none;border:none;color:#94a3b8;padding:0 3px;font-size:15px;border-radius:50%}.chip button:hover{color:#f87171}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:760px){.grid2{grid-template-columns:1fr}}
.note{color:#94a3b8;font-size:12px;margin-top:9px}
#warn{display:none;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.5);color:#fca5a5;border-radius:16px;padding:13px 16px;margin-bottom:16px;font-size:13px}
footer{color:#64748b;font-size:11px;text-align:center;margin-top:34px}
</style></head><body><div class=wrap>
<header>
 <div class=logo>🛡️</div>
 <div><h1>C3 AdBlock<small id=host>—</small></h1></div>
 <span class=pill id=stpill><span class=dot></span><span id=sttxt>—</span></span>
 <div class=sp></div>
 <select id=pausedur><option value=30>30 sn</option><option value=300 selected>5 dk</option><option value=1800>30 dk</option><option value=0>Ben açana dek</option></select>
 <button class=grad id=pausbtn onclick=togglePause()>⏸ Duraklat</button>
</header>
<div id=warn>⚠️ <b>Varsayılan şifre kullanılıyor.</b> <code>secrets.h</code> içindeki WEB_PASS/OTA_PASS hâlâ örnek değerler — herkes okuyabilir. Gerçek değerleri girip yeniden flaşlayın.</div>
<div class=hero>
 <div class="glass hpad donut">
  <svg width=140 height=140 viewBox="0 0 140 140">
   <defs><linearGradient id=gA x1=0 y1=0 x2=1 y2=1><stop offset=0 stop-color=#f87171/><stop offset=1 stop-color=#fbbf24/></linearGradient>
   <linearGradient id=gG x1=0 y1=0 x2=1 y2=1><stop offset=0 stop-color=#34d399/><stop offset=1 stop-color=#22d3ee/></linearGradient></defs>
   <circle cx=70 cy=70 r=56 fill=none stroke=rgba(255,255,255,.08) stroke-width=13/>
   <circle id=dnG cx=70 cy=70 r=56 fill=none stroke=url(#gG) stroke-width=13 stroke-linecap=round transform=rotate(-90 70 70) stroke-dasharray="0 351.9"/>
   <circle id=dnR cx=70 cy=70 r=56 fill=none stroke=url(#gA) stroke-width=13 stroke-linecap=round transform=rotate(-90 70 70) stroke-dasharray="0 351.9"/>
   <text x=70 y=65 text-anchor=middle fill=#e7ecf5 font-size=19 font-weight=800 id=donutpct>—</text>
   <text x=70 y=84 text-anchor=middle fill=#94a3b8 font-size=9.5>engellendi</text>
  </svg>
  <div class=legend><div class=lab>Dağılım</div>
   <div><i style="background:linear-gradient(90deg,#f87171,#fbbf24)"></i><span id=lgB>—</span> engellendi</div>
   <div><i style="background:linear-gradient(90deg,#34d399,#22d3ee)"></i><span id=lgA>—</span> geçti</div>
  </div>
 </div>
 <div class="glass hpad"><div class=lab>ENGELLENEN · TOPLAM</div><div class=big id=kB>—</div><div class=note id=rate>&nbsp;</div></div>
</div>
<div class=kpis>
 <div class="glass kpi"><div class=lab>✅ Geçen</div><div class=v id=kA>—</div></div>
 <div class="glass kpi"><div class=lab>📋 Blok listesi</div><div class=v id=kD>—</div></div>
 <div class="glass kpi"><div class=lab>📶 Sinyal</div><div class=v id=kR>—</div></div>
 <div class="glass kpi"><div class=lab>🌡️ Sıcaklık</div><div class=v id=kT>—</div></div>
 <div class="glass kpi"><div class=lab>💾 Boş RAM</div><div class=v id=kH>—</div></div>
 <div class="glass kpi"><div class=lab>⏱️ Çalışma</div><div class=v id=kU>—</div></div>
</div>
<h2>📶 İstemciler — <span id=cnum>0</span> cihaz</h2>
<div class=grid id=ct></div>
<div class=note>✎ tıkla → MAC'e bağlı kalıcı ad ver (mDNS adını ezer) · <i class="tg a">mDNS</i> cihazın ağdaki kendi adı · <i class="tg m">elle</i> senin verdiğin ad</div>
<h2>🚫 Özel engellenen domainler — <span id=dnum>0</span></h2>
<div class="glass hpad">
 <div style=display:flex;gap:8px;margin-bottom:10px><input id=dom placeholder="ads.example.com" style=flex:1><button class=grad onclick=addDom()>Engelle</button></div>
 <div id=chips></div>
</div>
<div class=grid2 style=margin-top:22px>
 <div><h2>📋 Blok listesi</h2><div class="glass hpad">
  <div style=display:flex;gap:8px;flex-wrap:wrap;align-items:center>
   <button class=grad id=fnb onclick=fetchNow()>⟳ Şimdi güncelle</button>
   <input id=uurl placeholder="https://host/blocklist.bin" style="flex:1;min-width:150px">
   <span style=color:#94a3b8>her</span><input id=uiv size=2 value=24><span style=color:#94a3b8>sa</span>
   <button onclick=saveUpd()>Kaydet</button>
  </div><div class=note>Son: <span id=ustat>—</span></div>
  <label class=up>⬆ <b>blocklist.bin</b> yükle — sürükle bırak veya seç<input type=file id=blf accept=.bin hidden></label>
  <div class=note id=upmsg>tools/build_blocklist.py ile üret, USB gerekmez</div>
 </div></div>
 <div><h2>⚙ Donanım & OTA</h2><div class="glass hpad">
  <label class=up style=margin-top:0>⬆ <b>firmware.bin</b> — OTA güncelleme<input type=file id=fwb accept=.bin hidden></label>
  <div class=note id=fwmsg>cihaz doğrular ve ~15 sn'de yeniden başlar</div>
  <button style=margin-top:10px onclick="if(confirm('Kayıtlı WiFi silinip kurulum portalına dönülecek. Emin misin?'))forgetWifi()">📡 WiFi unut</button>
 </div></div>
</div>
<footer>C3 AdBlock · <span id=demo></span>3 sn'de bir yenilenir</footer>
</div><script>
const H={'X-Requested-With':'c3-adblock'}
function fmt(n){return n.toLocaleString('tr-TR')}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
let prev=null
function togglePause(){fetch(stpill.className=='pill off'?'/resume':'/pause?s='+pausedur.value,{headers:H}).then(load)}
async function load(){let s;try{s=await(await fetch('/stats.json')).json()}catch(e){demo.textContent='demo — ';render(demodata());return}
render(s)}
function demodata(){return{ip:'192.168.1.64',blocked:128431,allowed:512097,domains:198879,rssi:-52,temp:41.5,heap:135168,uptime:'3g 4s 12d',blocking:true,resumeIn:0,upurl:'https://github.com/…/blocklist.bin',upiv:24,upstat:'ok: 198.879 domain',clients:[{ip:'192.168.1.10',mac:'a4:83:e7:11:22:33',blocked:2877,allowed:61203,banned:false,name:'semih-desktop',src:'man'},{ip:'192.168.1.23',mac:'f0:18:98:44:55:66',blocked:4102,allowed:38921,banned:false,name:'MacBook-Pro-Semih',src:'mdns'},{ip:'192.168.1.77',mac:'3c:5a:b4:77:88:99',blocked:9431,allowed:2105,banned:false,name:'Samsung TV Oda',src:'man'},{ip:'192.168.1.42',mac:'9e:31:f0:aa:bb:cc',blocked:1288,allowed:12044,banned:false,name:'iphone-ayse',src:'mdns'},{ip:'192.168.1.94',mac:'32:11:8e:dd:ee:ff',blocked:551,allowed:8443,banned:true,name:'Guest-Android',src:'man'}],custom:['ads.example.com','tracker.evil.io','telemetry.vendor.net'],defcreds:false}}
function render(s){
host.textContent='adblocker.local · '+s.ip+' · '+(s.uptime||'')
document.getElementById('warn').style.display=s.defcreds?'block':'none';
let on=s.blocking!==false
stpill.className=on?'pill':'pill off'
sttxt.textContent=on?'Engelleme aktif':(s.resumeIn>0?'Duraklatıldı — '+s.resumeIn+' sn sonra':'Duraklatıldı')
pausbtn.textContent=on?'⏸ Duraklat':'▶ Devam et';pausedur.style.display=on?'':'none'
let tot=s.blocked+s.allowed,frac=tot?s.blocked/tot:0,C=351.9
dnG.setAttribute('stroke-dasharray',(C*(1-frac)).toFixed(1)+' '+C)
dnR.setAttribute('stroke-dasharray',(C*frac).toFixed(1)+' '+C)
dnR.setAttribute('stroke-dashoffset',(-C*(1-frac)).toFixed(1))
donutpct.textContent=Math.round(frac*100)+'%';lgB.textContent=fmt(s.blocked);lgA.textContent=fmt(s.allowed)
kB.textContent=fmt(s.blocked);kA.textContent=fmt(s.allowed)
if(prev){let dt=(Date.now()-prev.t)/1000,r=(s.blocked-prev.b)/dt;rate.textContent=r>=0?'+ '+r.toFixed(1)+' sorgu/sn (canlı)':'\u00a0'}
prev={b:s.blocked,t:Date.now()}
kD.textContent=fmt(s.domains);kR.textContent=s.rssi+' dBm';kT.textContent=s.temp+' °C';kH.textContent=Math.round(s.heap/1024)+' KB';kU.textContent=s.uptime
cnum.textContent=s.clients.length
ct.innerHTML=s.clients.slice().sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>{
let nm=c.name||c.ip,totc=c.blocked+c.allowed,pct=totc?Math.round(c.blocked/totc*100):0
return `<div class="cl glass ${c.banned?'bz':''}"><div class=top><div class=av>${esc((nm[0]||'?').toUpperCase())}</div><div class=tt style=min-width:0><div class=nm>${esc(nm)}${c.src=='man'?' <i class="tg m">elle</i>':c.src=='mdns'?' <i class="tg a">mDNS</i>':''} <button class=pen data-mac="${c.mac}" data-nm="${esc(c.name||'')}">✎</button></div><div class=sub>${c.ip} · ${c.mac.slice(0,8)}</div></div></div><div class=bar><i style="width:${pct}%"></i></div><div class=nums><span class=bred><b>${fmt(c.blocked)}</b> 🚫</span><span class=agrn><b>${fmt(c.allowed)}</b> ✅</span><button class="ban ${c.banned?'unb':''}" data-ip="${c.ip}">${c.banned?'Aç':'Yasakla'}</button></div></div>`}).join('')
dnum.textContent=s.custom.length
chips.innerHTML=s.custom.length?s.custom.map(d=>`<span class=chip>${esc(d)}<button data-d="${esc(d)}">×</button></span>`).join(''):'<span class=note>henüz yok</span>'
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
ustat.textContent=s.upstat||'—'}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:H}).then(()=>{dom.value='';load()})}}
ct.addEventListener('click',e=>{let p=e.target.closest('.pen')
if(p){let n=prompt('Cihaz adı (boş = sil):',p.dataset.nm);if(n===null)return;fetch('/label?mac='+p.dataset.mac+'&n='+encodeURIComponent(n.trim()),{headers:H}).then(load);return}
let b=e.target.closest('.ban');if(b)fetch('/ban?ip='+b.dataset.ip,{headers:H}).then(load)})
chips.addEventListener('click',e=>{if(e.target.tagName=='BUTTON')fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:H}).then(load)})
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:H}).then(load)}
function fetchNow(){ustat.textContent='getiriliyor…';fetch('/fetchnow',{headers:H}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
function forgetWifi(){fetch('/forgetwifi',{headers:H}).then(r=>r.text()).then(t=>alert(t))}
fwb.onchange=async e=>{let f=e.target.files[0];if(!f)return;fwmsg.textContent='flaşlanıyor '+(f.size/1048576).toFixed(2)+' MB…'
let fd=new FormData();fd.append('f',f)
try{let r=await fetch('/update',{method:'POST',headers:H,body:fd});fwmsg.textContent=r.ok?'✓ yeniden başlıyor, ~15 sn içinde bağlan':'✗ '+await r.text()}catch(_){fwmsg.textContent='✓ yeniden başlıyor, ~15 sn içinde bağlan'}
fwb.value=''}
blf.onchange=async e=>{let f=e.target.files[0];if(!f)return;upmsg.textContent='yükleniyor '+(f.size/1048576).toFixed(2)+' MB…'
let fd=new FormData();fd.append('f',f)
try{let r=await fetch('/upload',{method:'POST',headers:H,body:fd});upmsg.textContent=r.ok?'✓ güncellendi':'✗ '+await r.text()}catch(_){upmsg.textContent='✗ yükleme başarısız'}
blf.value='';setTimeout(load,600)}
load();setInterval(load,3000);
</script></body></html>)HTML";
