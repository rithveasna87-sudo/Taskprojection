
/* ===== Script 1 ===== */
// ===== Multi-account login =====
// Each brand account only sees its own brand. NonbeerMKT is the manager and sees every brand.
// NOTE: passwords are stored only as salted SHA-256 hashes. Hashing hides them from casual viewing, but real security needs server-side auth.
// For real security on a public website, move authentication and data filtering to the server.
const ACCOUNTS = [
  {user:'Cambodia ED',     ph:'2066ba7011964729934550825b18d01f605db69e4aba6bd1fb4364e5af409c98', role:'brand',   brand:'CED'},
  {user:'IZE',             ph:'b952e07260b696824ef96f1aea710fae040ce3d74c17ba58077f583683acac9b', role:'brand',   brand:'IZE'},
  {user:'EXPREZ',          ph:'61622eec6f3a1157e1aaeb100382cfa6fbaeae7bedd9e309103eeee81b46d9da', role:'brand',   brand:'Exprezz'},
  {user:'Cambodia Water',  ph:'3577af97bce6e7191a379ddc365142abfad053ae398ed63b6577076293e63559', role:'brand',   brand:'CW'},
  {user:'Cambodia COLA',   ph:'9fabcead0b2d9012e3dfbc48af9e1c56d3b1dc374078f3bd7758ed75146f0875', role:'brand',   brand:'Cambodia COLA'},
  {user:'MV Management',   ph:'5cacaf1238c807684a4aea7f26edd15626deb51507ce59936ea99b18c43d4497', role:'brand',   brand:'B.P.S.MV Management'},
  {user:'Brand Love designer', ph:'6977b65f17738666a1555926f52e32ade9ad20f6b59c4acc18e6dadc083ee95b', role:'brand', brand:'Designer', dzName:'Brand Love designer', dzBrands:'*'},
  // ----- Designer logins: each designer only sees / gets notified about requests from their own brands -----
  // dzBrands: list of brand names, '*' = all brands, 'nonbeer' = every brand except the beer brands.
  // Brands not yet in the tracker (Beer, Lite Beer, Wurkz, Wurkz Ice, CSD, Dazz) are already listed, so they work as soon as those brands are added.
  {user:'Designer-Sing',    ph:'4c6263b43aa1f65e4fb07a83f5ac22f76869f30bf0984798f61e4038ef7df0e4', role:'brand', brand:'Designer', dzName:'Veysing', dzBrands:['Beer']},
  {user:'Designer-Both',    ph:'22504d24a76880494a72284abd6f15a7ac1af33efa9c6abf48ba6a16a83aee45', role:'brand', brand:'Designer', dzName:'Both',    dzBrands:['Lite Beer']},
  {user:'Designer-Chitra',  ph:'86686485cd90c9ce6a4ba4cbb07c3379f9280e9372f53fbef1cd4c1d94045c11', role:'brand', brand:'Designer', dzName:'Chitra',  dzBrands:['Beer']},
  {user:'Designer-Silong',  ph:'7938043933f40e14f1a9e5a919796c7622aefeeadde55fdbc6b9925ebc2cd851', role:'brand', brand:'Designer', dzName:'Silong',  dzBrands:['Wurkz','Wurkz Ice','CED','Cambodia ED']},
  {user:'Designer-Phanith', ph:'bcd8f716b99ca88c20463d2282af5fb27397ebd7b9978258622c8ea45c820026', role:'brand', brand:'Designer', dzName:'Phanith', dzBrands:['CW','Cambodia Water','CSD','Cambodia Sport Drink']},
  {user:'Designer-Mengan',  ph:'f654d6d8567df45536860e71186f861f1b4cb0b522d288be2c4c3e1b4d8fad33', role:'brand', brand:'Designer', dzName:'Mengan',  dzBrands:['Exprezz','Exprez','Dazz']},
  {user:'Designer-Kim',     ph:'10eeadd9ba2807320483163963b7b2c79e5f36b48c14c1cf1e366d7aae19c769', role:'brand', brand:'Designer', dzName:'Kim',     dzBrands:['IZE','Cambodia COLA']},
  {user:'Designer-Ly',      ph:'1460218d54e001837cf16fbef59bd21a9f80288cfca737334a3aedd09de67652', role:'brand', brand:'Designer', dzName:'Chhengly',dzBrands:'nonbeer', dzRemark:true},
  {user:'Designer-Lead',    ph:'f3f4af9ea18fd371f5db60cee814e0b0b11835fb35f3a54741bcb33bc961825c', role:'brand', brand:'Designer', dzName:'Sophal',  dzBrands:'*', dzRemark:true},
  {user:'NonbeerMKT',      ph:'167108c970746d4164b762cfbadcabd84c603d1c9f3a056696c0075eed97b8d5', role:'manager', brand:''}
];
function sha256(m){const K=[];for(let i=2,c=0;c<64;i++){let p=1;for(let j=2;j*j<=i;j++)if(i%j==0){p=0;break}if(p){K[c++]=(Math.pow(i,1/3)%1*4294967296)|0}}
const b=unescape(encodeURIComponent(m)),l=b.length,w=new Array((((l+8)>>6)+1)*16).fill(0);for(let i=0;i<l;i++)w[i>>2]|=b.charCodeAt(i)<<(24-(i%4)*8);w[l>>2]|=0x80<<(24-(l%4)*8);w[(((l+8)>>6)<<4)+15]=l*8;
let h=[];for(let i=2,c=0;c<8;i++){let p=1;for(let j=2;j*j<=i;j++)if(i%j==0){p=0;break}if(p){h[c++]=(Math.pow(i,.5)%1*4294967296)|0}}
const R=(x,n)=>(x>>>n)|(x<<(32-n));for(let o=0;o<w.length;o+=16){const t=w.slice(o,o+16);for(let i=16;i<64;i++){const a=t[i-15],c=t[i-2];t[i]=(t[i-16]+(R(a,7)^R(a,18)^(a>>>3))+t[i-7]+(R(c,17)^R(c,19)^(c>>>10)))|0}
let [a,b2,c,d,e,f,g,hh]=h;for(let i=0;i<64;i++){const T1=(hh+(R(e,6)^R(e,11)^R(e,25))+((e&f)^(~e&g))+K[i]+t[i])|0,T2=((R(a,2)^R(a,13)^R(a,22))+((a&b2)^(a&c)^(b2&c)))|0;hh=g;g=f;f=e;e=(d+T1)|0;d=c;c=b2;b2=a;a=(T1+T2)|0}
h=[h[0]+a,h[1]+b2,h[2]+c,h[3]+d,h[4]+e,h[5]+f,h[6]+g,h[7]+hh].map(x=>x|0)}
return h.map(x=>('00000000'+(x>>>0).toString(16)).slice(-8)).join('')}
const SESSION_KEY = 'teamTrackerUser';
let ACTIVE = null;
try{ const su = sessionStorage.getItem(SESSION_KEY); ACTIVE = ACCOUNTS.find(a=>a.user===su) || null; sessionStorage.removeItem('teamTrackerLoggedIn'); }catch(e){}
// Only the manager account may keep a Manager View session.
if(!ACTIVE || ACTIVE.role !== 'manager'){ try{ sessionStorage.removeItem('mgrAuthed'); sessionStorage.removeItem('mgrBrand'); }catch(e){} }
function findAccount(u,p){ const n = String(u||'').trim().toLowerCase(); return ACCOUNTS.find(a=>a.user.toLowerCase()===n && a.ph===sha256('tracker:'+n+':'+p)) || null; }
function lockBrand(){ return ACTIVE && ACTIVE.role==='brand' ? ACTIVE.brand : ''; }
const DZ_BEER_BRANDS=['Beer','Lite Beer'];
function dzNorm(s){return String(s||'').toLowerCase().replace(/[^a-z0-9]/g,'')}
function dzBrandIn(list,b){const n=dzNorm(b);return list.some(x=>dzNorm(x)===n)}
// Can this designer account see a design request that came from brand `b`?
function dzCanSee(acc,t){
  if(!acc||!acc.dzBrands||acc.dzBrands==='*')return true;
  const rb=t.requestedBy;
  if(!rb){return !t.createdBy||t.createdBy===acc.user}   // tasks the designer made by hand
  if(acc.dzBrands==='nonbeer')return !dzBrandIn(DZ_BEER_BRANDS,rb);
  return dzBrandIn(acc.dzBrands,rb);
}
// Which designer handles a brand? (first matching account — used for auto-assign)
function dzDesignerFor(brand){
  const a=ACCOUNTS.find(x=>x.brand==='Designer'&&Array.isArray(x.dzBrands)&&dzBrandIn(x.dzBrands,brand));
  return a?a.dzName:'';
}
function scopedTasks(){ const b = lockBrand(); if(!b)return tasks; const base=tasks.filter(t=>t.brand===b); return b==='Designer'?base.filter(t=>dzCanSee(ACTIVE,t)):base; }
const loginScreen = document.getElementById('loginScreen');
const logoutBtn = document.getElementById('logoutBtn');
function showTracker(){
  loginScreen.hidden = true;
  logoutBtn.style.display = 'inline-flex';
}
document.getElementById('loginForm').addEventListener('submit', function(e){
  e.preventDefault();
  const acc = findAccount(document.getElementById('loginUsername').value, document.getElementById('loginPassword').value);
  if(acc){
    ACTIVE = acc;
    sessionStorage.setItem(SESSION_KEY, acc.user);
    document.getElementById('loginError').style.display = 'none';
    document.getElementById('loginForm').reset();
    showTracker();
    if(typeof applyAccount === 'function') applyAccount();
    window.scrollTo(0,0);
  }else{
    document.getElementById('loginError').style.display = 'block';
  }
});
logoutBtn.addEventListener('click', function(){
  try{ sessionStorage.removeItem(SESSION_KEY); sessionStorage.removeItem('mgrAuthed'); sessionStorage.removeItem('mgrBrand'); }catch(e){}
  history.replaceState(null,'',location.pathname+location.search);
  location.reload();
});
if(ACTIVE) showTracker();

const KEY='team-project-tracker-v1';let tasks=load(),importRows=[],importHeaders=[],mapping={},importValidation=[];
function sortByOrder(list){const n=list.filter(t=>typeof t.order!=='number'),o=list.filter(t=>typeof t.order==='number').sort((a,b)=>a.order-b.order);return n.concat(o)}
function load(){try{return sortByOrder(JSON.parse(localStorage.getItem(KEY))||[])}catch{return []}}
// Shared storage: tasks are saved to the team database so everyone sees the same data.
let synced=null,syncing=Promise.resolve(),pendingSaves=0,unsaved=false,needRefresh=false;
function syncStatus(msg,bad){let el=document.getElementById('syncStatus');if(!el){el=document.createElement('div');el.id='syncStatus';el.style.cssText='position:fixed;right:14px;bottom:14px;z-index:50;padding:7px 12px;border-radius:999px;font:600 12px system-ui,sans-serif;box-shadow:0 4px 14px rgba(0,0,0,.12);transition:opacity .3s';document.body.appendChild(el)}el.textContent=msg;el.style.background=bad?'#3a1c21':'#123526';el.style.color=bad?'#f69a9f':'#6ee7a8';el.style.opacity='1';clearTimeout(el._t);if(!bad)el._t=setTimeout(()=>el.style.opacity='0',2500)}
function snapshot(list){return new Map(list.map(t=>[t.id,JSON.stringify(t)]))}
function save(){localStorage.setItem(KEY,JSON.stringify(tasks));if(!synced){unsaved=true;return}let cur=snapshot(tasks),upsert=tasks.filter(t=>synced.get(t.id)!==cur.get(t.id)),del=[...synced.keys()].filter(k=>!cur.has(k));if(!upsert.length&&!del.length)return;let bases={};upsert.forEach(t=>{let b=synced.get(t.id);if(b)bases[t.id]=JSON.parse(b)});synced=cur;pendingSaves++;syncStatus('Saving…');syncing=syncing.then(()=>fetch('/api/tasks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({upsert,bases,delete:del})}).then(r=>{if(!r.ok)throw new Error(r.status);syncStatus('Saved ✓ — visible to everyone')})).catch(()=>{synced=null;unsaved=true;syncStatus('Could not save to server — retrying…',true);setTimeout(()=>refresh(),4000)}).finally(()=>{pendingSaves--;if(!pendingSaves){needRefresh=false;refresh()}})}
async function refresh(){if(pendingSaves){needRefresh=true;return}let pushLocal=unsaved;try{let r=await fetch('/api/tasks',{cache:'no-store'});if(!r.ok)throw new Error(r.status);let server=sortByOrder(await r.json());if(pendingSaves){needRefresh=true;return}
// First time: move tasks that only exist in this browser up to the shared database.
let local=tasks;let firstSync=!localStorage.getItem(KEY+'-synced');synced=snapshot(server);unsaved=false;
if(pushLocal||firstSync){let ids=new Set(server.map(t=>t.id));let extra=pushLocal?local.filter(t=>synced.get(t.id)!==JSON.stringify(t)):local.filter(t=>!ids.has(t.id));
if(firstSync)localStorage.setItem(KEY+'-synced','1');
if(extra.length){let ex=new Set(extra.map(t=>t.id));tasks=[...extra,...server.filter(t=>!ex.has(t.id))];render();save();return}}
let changed=JSON.stringify(server)!==JSON.stringify(tasks);tasks=server;localStorage.setItem(KEY,JSON.stringify(tasks));if(changed){render();liveRefs()}}catch(e){syncStatus('Offline — showing data saved on this device',true)}}
refresh();setInterval(()=>{if(!document.hidden)refresh()},15000);
// Live updates: the server pushes an event as soon as anyone changes a task.
(function live(){if(!window.EventSource)return;let v='',es;function open(){es=new EventSource('/api/live'+(v?'?v='+encodeURIComponent(v):''));es.addEventListener('hello',e=>{v=e.data});es.addEventListener('change',e=>{v=e.data;refresh()});es.onerror=()=>{es.close();setTimeout(open,1000)}}open()})();document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh()});function liveRefs(){try{let m=document.getElementById('refsModal');if(m&&m.classList.contains('show')){let t=tasks.find(x=>x.id===document.getElementById('refForm').dataset.taskId);if(t)renderRefs(t)}}catch(e){}}function keepTeammateEdits(obj,eid){let snap=openSnap,live=eid&&tasks.find(t=>t.id===eid);if(!snap||!live||snap.id!==eid)return;const n=v=>v==null?'':v;for(const f of ['name','brand','priority','type','owner','startDate','deadline','progress','notes','designer']){if(n(snap[f])===n(obj[f])&&live[f]!==undefined)obj[f]=live[f]}const links=l=>(l||[]).filter(r=>!r.file).map(r=>r.url),s0=links(snap.refs),u=links(obj.refs),removed=s0.filter(x=>!u.includes(x)),added=u.filter(x=>!s0.includes(x)),liveRefs0=live.refs||[],keepLinks=liveRefs0.filter(r=>!r.file&&!removed.includes(r.url)),have=keepLinks.map(r=>r.url),newLinks=added.filter(x=>!have.includes(x)).map(x=>obj.refs.find(r=>!r.file&&r.url===x)||{url:x}),liveFiles=liveRefs0.filter(r=>r.file),newFiles=obj.refs.filter(r=>r.file&&!liveFiles.some(o=>o.url===r.url)&&!(snap.refs||[]).some(o=>o.url===r.url));obj.refs=keepLinks.concat(newLinks,liveFiles,newFiles)}function id(){return 'T-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,6)}function esc(s=''){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function dateFmt(d){return d?new Date(d+'T00:00:00').toLocaleDateString(): 'No deadline'}
const BRANDS=['CED','IZE','Exprezz','CW','Cambodia COLA','B.P.S.MV Management','Designer'];function brandPill(t){return (BRANDS.includes(t.brand)?`<span class="pill brand">${esc(t.brand)}</span>`:'')+(t.designerRequested?'<span class="pill" title="Designer requested">🎨 Designer</span>':'')}function normBrand(v){let n=String(v||'').toLowerCase().replace(/[^a-z0-9]/g,'');return BRANDS.find(b=>b.toLowerCase().replace(/[^a-z0-9]/g,'')===n)||''}const TYPES=['Digital','On-ground','Branding'];function typePill(t){return TYPES.includes(t.type)?`<span class="pill type-${t.type.toLowerCase().replace(/[^a-z]/g,'')}">${esc(t.type)}</span>`:''}function normType(v){let n=String(v||'').toLowerCase().replace(/[^a-z]/g,'');if(['digital','online','social','socialmedia'].includes(n))return 'Digital';if(['onground','onsite','offline','event','events','ground','field'].includes(n))return 'On-ground';if(['branding','brand'].includes(n))return 'Branding';return ''}
function render(){const tf=document.getElementById('typeFilter').value,q=document.getElementById('search').value.toLowerCase(),pf=document.getElementById('priorityFilter').value,sf=document.getElementById('statusFilter').value;let bf=document.getElementById('brandFilter').value;let filtered=tasks.filter(t=>(!window.sevFilter||(t.problems||[]).some(p=>p.severity===window.sevFilter))&&(!q||(t.name+' '+(t.owner||'')+' '+(t.brand||'')+' '+(t.notes||'')).toLowerCase().includes(q))&&(!bf||t.brand===bf)&&(!pf||t.priority===pf)&&(!tf||t.type===tf)&& (sf===''||(sf==='inprogress'?(t.progress>0&&t.progress<100):String(t.progress)===sf)));const countGroups=list=>({brand:list.filter(t=>t.brand!=='Designer').length,designer:list.filter(t=>t.brand==='Designer').length});const allGroups=countGroups(tasks),doneTasks=tasks.filter(t=>t.progress===100),progressTasks=tasks.filter(t=>t.progress>0&&t.progress<100);const doneGroups=countGroups(doneTasks),progressGroups=countGroups(progressTasks);document.getElementById('totalCount').textContent=tasks.length;document.getElementById('totalBrandCount').textContent=allGroups.brand;document.getElementById('totalDesignerCount').textContent=allGroups.designer;document.getElementById('doneCount').textContent=doneTasks.length;document.getElementById('doneBrandCount').textContent=doneGroups.brand;document.getElementById('doneDesignerCount').textContent=doneGroups.designer;document.getElementById('progressCount').textContent=progressTasks.length;document.getElementById('progressBrandCount').textContent=progressGroups.brand;document.getElementById('progressDesignerCount').textContent=progressGroups.designer;let _d=new Date(),_t0=new Date(_d.getFullYear(),_d.getMonth(),_d.getDate()),_k=x=>x.getFullYear()+'-'+String(x.getMonth()+1).padStart(2,'0')+'-'+String(x.getDate()).padStart(2,'0'),_from=_k(_t0),_to=_k(new Date(_t0.getFullYear(),_t0.getMonth(),_t0.getDate()+5));let alerts=tasks.filter(t=>t.deadline&&Number(t.progress)<100&&t.deadline>=_from&&t.deadline<=_to).sort((a,b)=>a.deadline.localeCompare(b.deadline));const alertGroups=countGroups(alerts);document.getElementById('problemCount').textContent=alerts.length;document.getElementById('alertBrandCount').textContent=alertGroups.brand;document.getElementById('alertDesignerCount').textContent=alertGroups.designer;document.getElementById('problemCount2').textContent=alerts.length;document.getElementById('deadlineList').innerHTML=alerts.length?alerts.map(t=>{let dd=Math.round((new Date(t.deadline+'T00:00:00')-_t0)/864e5);return `<div class="alert-row"><div class="an">${esc(t.name)}<small>${dd===0?'Due today':dd===1?'Due tomorrow':'Due in '+dd+' days'} · ${dateFmt(t.deadline)}</small></div><div class="ao">${esc(t.owner||'Unassigned')}</div></div>`}).join(''):'<div class="small" style="padding:6px 10px">No deadlines in the next 5 days.</div>';let issues=tasks.flatMap(t=>(t.problems||[]).filter(p=>!p.resolved).map(p=>({...p,taskName:t.name,taskId:t.id})));{let _s=(document.getElementById('issueSort')||{}).value||'';if(_s){let _r={Low:1,Medium:2,High:3};issues.sort((x,y)=>_s==='high'?(_r[y.severity]||0)-(_r[x.severity]||0):(_r[x.severity]||0)-(_r[y.severity]||0))}}document.getElementById('issueBadge').textContent=issues.length+' open';document.getElementById('issueList').innerHTML=issues.length?issues.map(p=>`<div class="issue"><strong>${esc(p.title)} <span class="pill ${p.severity==='High'?'urgent':p.severity==='Medium'?'important':''}">${esc(p.severity)}</span></strong><p>${esc(p.taskName)} · ${esc(p.reporter||'Team member')}</p><p>${esc(p.details||'No additional details')}</p><button class="text-btn" onclick="resolveProblem('${p.taskId}','${p.id}')">Mark resolved</button></div>`).join(''):'<div class="empty">No problems reported yet.</div>';
document.getElementById('taskList').innerHTML=filtered.length?filtered.map(t=>`<article class="task" data-id="${t.id}"><div class="task-top"><div class="task-head"><span class="drag-handle" role="button" tabindex="0" title="Drag to reorder (or press ↑ / ↓)" aria-label="Reorder project">⋮⋮</span><div><div class="task-title">${esc(t.name)}</div><div class="meta">${[t.owner?esc(t.owner):'',t.deadline?'Due '+dateFmt(t.deadline):'',t.progress+'%'].filter(Boolean).join(' · ')}</div></div></div><div class="pills">${brandPill(t)}${typePill(t)}<span class="pill ${t.priority.toLowerCase()}">${esc(t.priority)}</span>${(t.problems||[]).some(p=>!p.resolved)?'<span class="pill urgent">Has problem</span>':''}</div></div><div class="progress"><div class="fill" style="width:${t.progress}%"></div></div><div class="steps">${[0,25,50,75,100].map(n=>`<button class="step ${t.progress===n?'active':t.progress>n?'passed':''}" onclick="setProgress('${t.id}',${n})">${n}%</button>`).join('')}</div>${t.notes?`<div class="meta task-note">${esc(t.notes)}</div>`:''}<div class="task-bottom"><div class="task-links"><button class="text-btn problem" onclick="openProblem('${t.id}')">Report a problem</button><button class="text-btn" onclick="showRefs('${t.id}')">References (${(t.refs||[]).length})</button></div><div class="task-links"><button class="text-btn" onclick="editTask('${t.id}')">Edit</button><button class="text-btn" style="color:#df4b55" onclick="deleteTask('${t.id}')">Delete</button></div></div></article>`).join(''):'<div class="empty">No tasks found. Add a task or change your filters.</div>'}
let openSnap=null;function openTask(t){openSnap=t?JSON.parse(JSON.stringify(t)):null;document.getElementById('taskModalTitle').textContent=t?'Edit task':'Add task';document.getElementById('editId').value=t?.id||'';document.getElementById('taskName').value=t?.name||'';document.getElementById('taskBrand').value=t?.brand||'';document.getElementById('taskPriority').value=t?.priority||'Normal';document.getElementById('taskType').value=t?.type||'';document.getElementById('taskOwner').value=t?.owner||'';document.getElementById('taskStartDate').value=t?.startDate||'';document.getElementById('taskDeadline').value=t?.deadline||'';document.getElementById('taskProgress').value=t?.progress??0;document.getElementById('taskNotes').value=t?.notes||'';document.getElementById('taskRefs').value=(t?.refs||[]).filter(r=>!r.file).map(r=>r.url).join('\n');document.getElementById('taskFiles').value='';{let n=(t?.refs||[]).filter(r=>r.file).length;document.getElementById('taskFilesNote').textContent=(n?n+' file(s) already attached — manage them under References. ':'')+'Up to 5 MB per file.'}show('taskModal')}
function show(x){document.getElementById(x).classList.add('show')}function hide(x){document.getElementById(x).classList.remove('show')}function editTask(i){openTask(tasks.find(t=>t.id===i))}function deleteTask(i){if(confirm('Delete this task and its problem reports?')){tasks=tasks.filter(t=>t.id!==i);save();render()}}function setProgress(i,p){let t=tasks.find(t=>t.id===i);if(t){t.progress=p;save();render()}}function openProblem(i){let t=tasks.find(t=>t.id===i);document.getElementById('problemTaskId').value=i;document.getElementById('problemTaskLabel').textContent='Task: '+t.name;document.getElementById('problemForm').reset();show('problemModal')}function resolveProblem(tid,pid){let t=tasks.find(x=>x.id===tid),p=t?.problems.find(x=>x.id===pid);if(p){p.resolved=true;save();render()}}function showRefs(i){let t=tasks.find(x=>x.id===i);document.getElementById('refsTaskLabel').textContent=t.name;document.getElementById('refForm').dataset.taskId=i;renderRefs(t);show('refsModal')}const MAX_FILE=5*1024*1024;async function uploadFile(f){if(f.size>MAX_FILE)throw new Error(f.name+' is larger than 5 MB.');let r=await fetch('/api/files',{method:'POST',headers:{'Content-Type':f.type||'application/octet-stream','X-File-Name':encodeURIComponent(f.name)},body:f});if(!r.ok)throw new Error('Could not upload '+f.name+(r.status===413?' (too large)':''));let d=await r.json();return{name:f.name,url:d.url,file:true,type:d.type,size:d.size}}function sizeFmt(b){return b>=1048576?(b/1048576).toFixed(1)+' MB':Math.max(1,Math.round(b/1024))+' KB'}function renderRefs(t){document.getElementById('refsDisplay').innerHTML=(t.refs||[]).length?t.refs.map((r,n)=>`<div class="ref-item"><span><b>${r.file?(String(r.type||'').startsWith('image/')?'🖼️ ':'📎 '):''}${esc(r.name||'Reference')}</b><br><a href="${esc(r.url)}" target="_blank" rel="noopener">${r.file?'Open file'+(r.size?' ('+sizeFmt(r.size)+')':''):esc(r.url)}</a>${r.file&&String(r.type||'').startsWith('image/')?`<a href="${esc(r.url)}" target="_blank" rel="noopener"><img class="ref-thumb" src="${esc(r.url)}" alt="${esc(r.name||'Photo')}" loading="lazy"></a>`:''}</span><button class="text-btn problem" onclick="removeRef('${t.id}',${n})">Remove</button></div>`).join(''):'<div class="empty">No references yet. Add a link, file or photo below.</div>'}function removeRef(tid,n){let t=tasks.find(x=>x.id===tid);if(t){let [r]=t.refs.splice(n,1);if(r?.file&&r.url.startsWith('/api/files/'))fetch(r.url,{method:'DELETE'}).catch(()=>{});save();renderRefs(t);render()}}document.getElementById('refForm').onsubmit=async e=>{e.preventDefault();let form=e.currentTarget,btn=document.getElementById('refSubmit'),tid=form.dataset.taskId,t=tasks.find(x=>x.id===tid),url=document.getElementById('refUrl').value.trim(),name=document.getElementById('refName').value.trim(),files=[...document.getElementById('refFile').files];if(!t)return;if(!url&&!files.length){alert('Add a reference URL or choose a file / photo.');return}let added=[];if(files.length){btn.disabled=true;btn.textContent='Uploading…';try{for(const f of files){let r=await uploadFile(f);if(name&&files.length===1&&!url)r.name=name;added.push(r)}}catch(err){alert(err.message);btn.disabled=false;btn.textContent='＋ Add reference';return}btn.disabled=false;btn.textContent='＋ Add reference'}t=tasks.find(x=>x.id===tid)||t;t.refs=t.refs||[];if(url)t.refs.push({name:name||'Reference',url});t.refs.push(...added);save();form.reset();renderRefs(t);render()};
document.getElementById('addBtn').onclick=()=>openTask();document.getElementById('taskForm').onsubmit=async e=>{e.preventDefault();let form=e.currentTarget,btn=form.querySelector('button[type=submit]'),eid=document.getElementById('editId').value,old=tasks.find(t=>t.id===eid),oldRefs=old?.refs||[],refs=document.getElementById('taskRefs').value.split(/\n/).map(x=>x.trim()).filter(Boolean).map(url=>oldRefs.find(r=>!r.file&&r.url===url)||{url});refs=refs.concat(oldRefs.filter(r=>r.file));let files=[...document.getElementById('taskFiles').files];if(files.length){btn.disabled=true;btn.textContent='Uploading…';try{for(const f of files)refs.push(await uploadFile(f))}catch(err){alert(err.message);btn.disabled=false;btn.textContent='Save task';return}btn.disabled=false;btn.textContent='Save task'}let obj={id:eid||id(),name:document.getElementById('taskName').value.trim(),brand:document.getElementById('taskBrand').value,priority:document.getElementById('taskPriority').value,type:document.getElementById('taskType').value,owner:document.getElementById('taskOwner').value.trim(),startDate:document.getElementById('taskStartDate').value,deadline:document.getElementById('taskDeadline').value,progress:Number(document.getElementById('taskProgress').value),notes:document.getElementById('taskNotes').value.trim(),refs,problems:old?.problems||[],taskId:old?.taskId||'',order:old?.order,designerRequested:!!old?.designerRequested,requestedBy:old?.requestedBy,fromTask:old?.fromTask,createdBy:old?.createdBy||(lockBrand()==='Designer'&&!old?ACTIVE.user:undefined),designer:document.getElementById('dzDesignerRow').style.display==='none'?(old?.designer||''):document.getElementById('taskDesigner').value.trim()};if(old&&old.archived){obj.archived=old.archived;obj.archivedAt=old.archivedAt}if(old){if(lockBrand()==='Designer')obj.editedAt=new Date().toISOString();else if(old.editedAt)obj.editedAt=old.editedAt}keepTeammateEdits(obj,eid);dzMaybeRequest(obj);if(old)tasks=tasks.map(t=>t.id===eid?obj:t);else tasks.unshift(obj);save();hide('taskModal');render()};document.getElementById('problemForm').onsubmit=e=>{e.preventDefault();let t=tasks.find(x=>x.id===document.getElementById('problemTaskId').value);if(t){t.problems=t.problems||[];t.problems.unshift({id:id(),title:document.getElementById('problemTitle').value.trim(),severity:document.getElementById('problemSeverity').value,reporter:document.getElementById('problemReporter').value.trim(),details:document.getElementById('problemDetails').value.trim(),resolved:false,createdAt:new Date().toISOString()});save();hide('problemModal');render()}};
document.querySelectorAll('[data-close]').forEach(b=>b.onclick=()=>hide(b.dataset.close));['search','priorityFilter','brandFilter','typeFilter','statusFilter'].forEach(x=>document.getElementById(x).addEventListener('input',()=>render()));
// Excel export
function exportExcelLegacy(){if(!window.XLSX){alert('Excel tools need an internet connection.');return}let rows=scopedTasks().map(t=>({'Task ID':t.taskId||t.id,'Task Name':t.name,'Brand':t.brand||'','Priority':t.priority,'Type':t.type||'','Assigned To':t.owner,'Start Date':t.startDate||'','Deadline':t.deadline,'Progress':t.progress,'Status':t.progress===100?'Completed':t.progress===0?'Not Started':'In Progress','Problem':(t.problems||[]).filter(p=>!p.resolved).map(p=>p.title).join('; '),'References':(t.refs||[]).map(r=>r.file?location.origin+r.url:r.url).join('; '),'Notes':t.notes}));let ws=XLSX.utils.json_to_sheet(rows),wb=XLSX.utils.book_new();XLSX.utils.book_append_sheet(wb,ws,'Tasks');XLSX.writeFile(wb,'team-project-tasks.xlsx')}// ===== Excel export: "Master Timeline" template (one sheet per brand, Gantt style) =====
function mtBuild(ExcelJS,list){
  const TITLES={'CED':'CAMBODIA ED','IZE':'IZE','Exprezz':'EXPREZZ','CW':'CAMBODIA WATER','Cambodia COLA':'CAMBODIA COLA','B.P.S.MV Management':'B.P.S. MV MANAGEMENT','Designer':'DESIGN REQUESTS'};
  const SHEETS={'CED':'Cambodia ED','CW':'Cambodia Water','Designer':'Design Requests'};
  const col=n=>{let s='';while(n>0){const m=(n-1)%26;s=String.fromCharCode(65+m)+s;n=Math.floor((n-1)/26)}return s};
  const U=s=>{const m=/^(\d{4})-(\d{2})-(\d{2})/.exec(s||'');return m?new Date(Date.UTC(+m[1],+m[2]-1,+m[3])):null};
  const solid=a=>({type:'pattern',pattern:'solid',fgColor:{argb:'FF'+a}});
  const cfFill=a=>({fill:{type:'pattern',pattern:'solid',bgColor:{argb:'FF'+a}}});
  const hair={style:'thin',color:{argb:'FFD9D9D9'}};
  const wb=new ExcelJS.Workbook();wb.creator='Team Project Tracker';wb.created=new Date();
  wb.calcProperties={fullCalcOnLoad:true};
  const groups=new Map();
  list.forEach(t=>{const k=t.brand||'Other';if(!groups.has(k))groups.set(k,[]);groups.get(k).push(t)});
  const usedNames=new Set(),todayU=(()=>{const d=new Date();return new Date(Date.UTC(d.getFullYear(),d.getMonth(),d.getDate()))})();
  groups.forEach((tasks,brand)=>{
    let name=(SHEETS[brand]||brand).replace(/[\\\/?*\[\]:]/g,' ').slice(0,31),n=2,base=name;
    while(usedNames.has(name.toLowerCase())){name=base.slice(0,28)+' '+n++}
    usedNames.add(name.toLowerCase());
    const ws=wb.addWorksheet(name,{views:[{state:'frozen',xSplit:14,ySplit:7,showGridLines:true}],pageSetup:{orientation:'landscape',fitToPage:true,fitToWidth:1,fitToHeight:0}});
    // --- prepare rows
    const rows=tasks.map(t=>{
      let s=U(t.startDate)||U(t.deadline),e=U(t.deadline)||s;
      if(s&&e&&e<s)e=s;
      const open=(t.problems||[]).filter(p=>!p.resolved).map(p=>p.title);
      const prog=Math.max(0,Math.min(100,Number(t.progress)||0));
      const status=t.archived==='removed'?'Removed':prog>=100?'Completed':prog>0?'In Progress':'Not Started';
      const lines=[];
      if(t.brief&&t.brief.eventName)lines.push('Event: '+t.brief.eventName);
      if(t.notes)lines.push(String(t.notes).trim());
      if(t.priority&&t.priority!=='Normal')lines.push('Priority: '+t.priority);
      if(open.length)lines.push('⚠ Problem: '+open.join('; '));
      if(t.designer&&t.brand!=='Designer')lines.push('Designer: '+t.designer);
      return {t,s,e,prog,status,detail:lines.join('\n'),
        brandTxt:t.brand==='Designer'?String(t.requestedBy||'Designer').toUpperCase():(TITLES[t.brand]||String(t.brand||'').toUpperCase()),
        lead:t.brand==='Designer'?(t.designer||''):(t.owner||'')};
    });
    // group by project type
    const order=[],byType={};
    rows.forEach(r=>{const k=r.t.type||'General';if(!byType[k]){byType[k]=[];order.push(k)}byType[k].push(r)});
    order.forEach(k=>byType[k].sort((a,b)=>((a.s||a.e||0)-(b.s||b.e||0))));
    // --- timeline range
    const starts=rows.map(r=>r.s).filter(Boolean),ends=rows.map(r=>r.e).filter(Boolean);
    const first=starts.length?new Date(Math.min(...starts)):todayU;
    const lastD=ends.length?new Date(Math.max(...ends)):first;
    const mon=new Date(first.getTime()+(2-(first.getUTCDay()+1))*864e5);
    const weeks=Math.min(30,Math.max(8,Math.ceil(((lastD-mon)/864e5+1)/7)));
    const G0=15,LAST=14+weeks*7;
    // --- column widths
    [[1,5.8],[2,1.9],[3,12.4],[4,51.2],[5,16.5],[6,15.7],[7,44.7],[8,11.1],[9,10],[10,6],[11,11.3],[12,6.7],[13,6.8],[14,1.5]].forEach(([c,w])=>ws.getColumn(c).width=w);
    for(let c=G0;c<=LAST;c++)ws.getColumn(c).width=2.6;
    // --- banner rows 1-3
    ws.getRow(1).height=40.5;ws.getRow(2).height=18;ws.getRow(3).height=11.25;ws.getRow(4).height=18;ws.getRow(5).height=14.25;ws.getRow(6).height=9.5;ws.getRow(7).height=30;
    for(let c=1;c<=LAST;c++){
      ws.getCell(1,c).fill=solid('1243A6');ws.getCell(2,c).fill=solid('95B3D7');ws.getCell(3,c).fill=solid('DCE6F1');
      for(let r=4;r<=6;r++)ws.getCell(r,c).fill=solid('DCE6F1');
    }
    const title=ws.getCell('D1');title.value=TITLES[brand]||String(brand).toUpperCase();
    title.font={name:'Arial',size:22,bold:true,color:{argb:'FFFFFFFF'}};title.alignment={vertical:'middle',horizontal:'left'};
    const lab={name:'Arial',size:11,color:{argb:'FF366092'}};
    const med={style:'medium',color:{argb:'FFDCE6F1'}};
    const put=(addr,val,extra)=>{const c=ws.getCell(addr);c.value=val;c.font=lab;Object.assign(c,extra||{});return c};
    put('D4','Project Start Date',{alignment:{horizontal:'right',vertical:'middle'}});
    ws.mergeCells('F4:H4');put('F4',first,{numFmt:'m/d/yyyy'});
    ws.getCell('D5').value='Brand Lead';ws.getCell('D5').font=lab;ws.getCell('D5').alignment={horizontal:'right',vertical:'middle'};
    // most common lead = brand lead
    const cnt={};rows.forEach(r=>{if(r.lead&&r.t.brand!=='Designer')cnt[r.lead]=(cnt[r.lead]||0)+1});
    const LEADS={'CED':'Vanneath','IZE':'Vanneath','CW':'Socheat','Exprezz':'Sivly','Cambodia COLA':'Kinal','B.P.S.MV Management':'Thearo','Designer':'Sophal'};
    const lead=LEADS[brand]||Object.keys(cnt).sort((a,b)=>cnt[b]-cnt[a])[0]||'';
    ws.mergeCells('F5:H5');put('F5',lead);
    ['F4','F5'].forEach(a=>{const c=ws.getCell(a);c.fill=solid('FFFFFF');c.alignment={horizontal:'center',vertical:'middle'};c.border={bottom:med,top:med,left:med,right:med}});
    ws.getCell('F4').numFmt='m/d/yyyy';
    put('L4','Display Week',{alignment:{horizontal:'right',vertical:'middle'}});
    const dw=ws.getCell('M4');dw.value=1;dw.font=lab;dw.fill=solid('FFFFFF');dw.alignment={horizontal:'center',vertical:'middle'};dw.border={bottom:med,top:med,left:med,right:med};
    // --- week / date / day-letter header rows
    for(let w=0;w<weeks;w++){
      const c=G0+7*w,L=col(c);
      ws.mergeCells(4,c,4,c+6);ws.mergeCells(5,c,5,c+6);
      const a=ws.getCell(4,c);a.value={formula:'"Week "&('+L+'6-($F$4-WEEKDAY($F$4,1)+2))/7+1'};a.font=lab;a.alignment={horizontal:'center',vertical:'middle'};
      const b=ws.getCell(5,c);b.value={formula:L+'6'};b.numFmt='d mmm yyyy';b.font={name:'Arial',size:9,bold:true,color:{argb:'FF366092'}};b.alignment={horizontal:'center',vertical:'middle'};
    }
    for(let c=G0;c<=LAST;c++){
      const L=col(c),d=ws.getCell(6,c);
      d.value={formula:c===G0?'$F$4-WEEKDAY($F$4,1)+2+7*($M$4-1)':col(c-1)+'6+1'};d.numFmt='d';
      d.font={name:'Arial',size:8,bold:true,color:{argb:'FF366092'}};d.alignment={horizontal:'center',vertical:'middle'};
      const l=ws.getCell(7,c);l.value={formula:'CHOOSE(WEEKDAY('+L+'6,1),"S","M","T","W","T","F","S")'};
      l.font={name:'Arial',size:8,color:{argb:'FFFFFFFF'}};l.fill=solid('BFBFBF');l.alignment={horizontal:'center',vertical:'middle'};
    }
    // --- column header row 7
    const H=['WBS','','BRAND PILLAR','TASK','BRAND','LEAD','DETAIL PROJECT','START','END','DAYS','REMARK\n(Daily check progress)','% DONE','WORK DAYS',''];
    H.forEach((txt,i)=>{
      const c=ws.getCell(7,i+1);c.value=txt||null;
      c.fill=solid(i===10?'FF9900':'A6A6A6');
      c.font={name:'Arial',size:8,bold:true,color:{argb:'FFFFFFFF'}};
      c.alignment={horizontal:(i===0||i===3||i===2)?'left':'center',vertical:'middle',wrapText:true};
    });
    // --- data rows
    let r=8;
    order.forEach((type,gi)=>{
      for(let c=1;c<=LAST;c++){const x=ws.getCell(r,c);x.fill=solid('99CCFF');x.border={bottom:hair}}
      const wbs=ws.getCell(r,1);wbs.value=String(gi+1);wbs.font={name:'Calibri',size:11,bold:true,color:{argb:'FF595959'}};
      const g=ws.getCell(r,4);g.value=type;g.font={name:'Calibri',size:11,bold:true};g.alignment={vertical:'middle'};
      ws.getRow(r).height=19;r++;
      byType[type].forEach((x,ti)=>{
        const row=ws.getRow(r);
        const lines=Math.max(1,x.detail?x.detail.split('\n').reduce((a,s)=>a+Math.ceil(s.length/52)||a+1,0):1,Math.ceil(String(x.t.name||'').length/58));
        row.height=Math.max(15,lines*12+3);
        const base={name:'Calibri',size:9};
        const set=(c,v,o)=>{const cell=ws.getCell(r,c);if(v!==undefined)cell.value=v;cell.font=Object.assign({},base,o&&o.font||{});cell.alignment=Object.assign({vertical:'middle'},o&&o.al||{});if(o&&o.fill)cell.fill=solid(o.fill);if(o&&o.nf)cell.numFmt=o.nf;cell.border={bottom:hair};return cell};
        set(1,String(gi+1)+'.'+(ti+1),{font:{bold:true,color:{argb:'FF595959'},size:8}});
        set(2,null);
        set(3,x.t.type||'',{font:{bold:true,color:{argb:'FF595959'}},fill:'F2F2F2',al:{horizontal:'left',wrapText:true}});
        set(4,x.t.name||'',{al:{horizontal:'left',wrapText:true}});
        set(5,x.brandTxt,{font:{bold:true,color:{argb:'FFFFFFFF'}},fill:'0070C0',al:{horizontal:'center',wrapText:true}});
        set(6,x.lead,{al:{horizontal:'center',wrapText:true}});
        set(7,x.detail,{al:{horizontal:'left',wrapText:true}});
        set(8,x.s||null,{nf:'m/d/yyyy',al:{horizontal:'center'}});
        set(9,x.e||null,{nf:'m/d/yyyy',al:{horizontal:'center'}});
        set(10,{formula:'IF(OR(I'+r+'=0,H'+r+'=0),0,I'+r+'-H'+r+'+1)'},{nf:'0',al:{horizontal:'center'}});
        set(11,x.status,{al:{horizontal:'center',wrapText:true}});
        set(12,x.prog/100,{nf:'0%',al:{horizontal:'center'}});
        set(13,{formula:'IF(OR(I'+r+'=0,H'+r+'=0),0,NETWORKDAYS(H'+r+',I'+r+'))'},{nf:'0',fill:'F2F2F2',al:{horizontal:'right'}});
        for(let c=G0;c<=LAST;c++)ws.getCell(r,c).border={bottom:hair};
        r++;
      });
    });
    const end=r-1;
    ws.autoFilter={from:{row:7,column:1},to:{row:7,column:13}};
    // --- conditional formatting (same rules as the template)
    ws.addConditionalFormatting({ref:col(G0)+'6:'+col(LAST)+end,rules:[{type:'expression',priority:1,formulae:[col(G0)+'$6=TODAY()'],style:{border:{left:{style:'thin',color:{argb:'FFE46C0A'}},right:{style:'thin',color:{argb:'FFE46C0A'}}}}}]});
    ws.addConditionalFormatting({ref:col(G0)+'8:'+col(LAST)+end,rules:[
      {type:'expression',priority:2,formulae:['AND($H8<>"",$H8<='+col(G0)+'$6,ROUNDDOWN(($I8-$H8+1)*$L8,0)+$H8-1>='+col(G0)+'$6)'],style:cfFill('7F7F7F')},
      {type:'expression',priority:3,formulae:['AND(NOT(ISBLANK($H8)),$H8<='+col(G0)+'$6,$I8>='+col(G0)+'$6)'],style:cfFill('0070C0')}]});
    const wf={font:{color:{argb:'FFFFFFFF'},bold:true}};
    ws.addConditionalFormatting({ref:'K8:K'+end,rules:[
      {type:'cellIs',priority:4,operator:'equal',formulae:['"Completed"'],style:Object.assign({},cfFill('00B0F0'),wf)},
      {type:'cellIs',priority:5,operator:'equal',formulae:['"In Progress"'],style:Object.assign({},cfFill('00B050'),wf)},
      {type:'cellIs',priority:6,operator:'equal',formulae:['"Not Started"'],style:cfFill('D9D9D9')},
      {type:'cellIs',priority:7,operator:'equal',formulae:['"Removed"'],style:Object.assign({},cfFill('FF0000'),wf)}]});
  });
  return wb;
}
async function exportExcel(){
  const list=scopedTasks();
  if(!list.length){alert('There are no tasks to export yet.');return}
  if(!window.ExcelJS){exportExcelLegacy();return}
  try{
    const wb=mtBuild(window.ExcelJS,list),buf=await wb.xlsx.writeBuffer();
    const d=new Date(),stamp=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
    const b=lockBrand(),tag=b?'-'+b.replace(/[^A-Za-z0-9]+/g,'-'):'';
    const url=URL.createObjectURL(new Blob([buf],{type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}));
    const a=document.createElement('a');a.href=url;a.download='Master-Timeline'+tag+'-'+stamp+'.xlsx';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),4000);
  }catch(err){console.error(err);exportExcelLegacy()}
}

document.getElementById('exportBtn').onclick=exportExcel;
// Excel import
const fields=[['taskId','Task ID'],['name','Task Name'],['brand','Brand'],['priority','Priority'],['type','Type'],['owner','Assigned To'],['startDate','Start Date'],['deadline','Deadline'],['progress','Progress'],['problem','Problem'],['refs','References'],['notes','Notes']];function norm(s){return String(s||'').toLowerCase().replace(/[^a-z0-9]/g,'')}const aliases={taskId:['taskid','id'],name:['task','taskname','name','title'],brand:['brand','brands'],priority:['priority','urgency'],type:['type','projecttype','category'],owner:['assignedto','assigned','owner','assignee','responsible'],startDate:['startdate','start','begindate'],deadline:['deadline','duedate','date'],progress:['progress','completion','percentcomplete','percentage'],problem:['problem','issue','blocker'],refs:['references','reference','ref','url','link'],notes:['notes','description','details']};function guess(headers){let m={};fields.forEach(([key])=>{let hit=headers.find(h=>aliases[key].includes(norm(h)));m[key]=hit||''});return m}
document.getElementById('importBtn').onclick=()=>{document.getElementById('importStep1').hidden=false;document.getElementById('importStep2').hidden=true;document.getElementById('confirmImport').disabled=true;document.getElementById('importInput').value='';show('importModal')};document.getElementById('importInput').onchange=async e=>{let f=e.target.files[0];if(!f)return;if(!window.XLSX){alert('Excel import needs an internet connection.');return}try{let data=await f.arrayBuffer(),wb=XLSX.read(data,{type:'array',cellDates:true}),sheet=wb.Sheets[wb.SheetNames[0]],json=XLSX.utils.sheet_to_json(sheet,{defval:'',raw:false});if(!json.length)throw Error('No task rows found in the first worksheet.');importRows=json;importHeaders=Object.keys(json[0]);mapping=guess(importHeaders);buildMapping();document.getElementById('importStep1').hidden=true;document.getElementById('importStep2').hidden=false;validateImport()}catch(err){alert('Could not read this file: '+err.message)}};
function buildMapping(){document.getElementById('mappingGrid').innerHTML=fields.map(([key,label])=>`<div class="mapping-row"><label>${label}${key==='name'?' *':''}</label><select class="field map-select" data-key="${key}"><option value="">— Not mapped —</option>${importHeaders.map(h=>`<option value="${esc(h)}" ${mapping[key]===h?'selected':''}>${esc(h)}</option>`).join('')}</select></div>`).join('');document.querySelectorAll('.map-select').forEach(s=>s.onchange=()=>{mapping[s.dataset.key]=s.value;validateImport()})}
function parseProgress(v){if(v===''||v==null)return 0;let n=Number(String(v).replace('%','').trim());if(!Number.isFinite(n))return NaN;if(n<=1&&String(v).includes('.'))n=n*100;return n}function parseDate(v){if(!v)return '';if(v instanceof Date&&!isNaN(v))return v.toISOString().slice(0,10);let s=String(v).trim();if(/^\d{4}-\d{1,2}-\d{1,2}/.test(s))return s.slice(0,10);let d=new Date(s);return isNaN(d)?null:d.toISOString().slice(0,10)}function findDuplicate(row){let rid=String(row.taskId||'').trim();if(rid){let byId=scopedTasks().find(t=>(t.taskId||t.id)===rid);if(byId)return byId}return scopedTasks().find(t=>t.name.trim().toLowerCase()===String(row.name).trim().toLowerCase())}
function validateImport(){let valid=0,errors=0,warnings=0;importValidation=importRows.map((r,i)=>{let get=k=>mapping[k]?r[mapping[k]]:'';let row={taskId:String(get('taskId')||'').trim(),name:String(get('name')||'').trim(),brand:lockBrand()||normBrand(get('brand')),priority:String(get('priority')||'Normal').trim(),type:normType(get('type')),owner:String(get('owner')||'').trim(),startDate:parseDate(get('startDate')),deadline:parseDate(get('deadline')),progress:parseProgress(get('progress')),problem:String(get('problem')||'').trim(),refs:String(get('refs')||'').trim(),notes:String(get('notes')||'').trim()};let errs=[],warn=[];if(mapping.type&&String(get('type')||'').trim()&&!row.type)warn.push('Unknown type; left blank');if(!row.brand)warn.push(mapping.brand&&String(get('brand')||'').trim()?'Unknown brand; left blank':'No brand');if(!mapping.name||!row.name)errs.push('Task name is required');if(!['Urgent','Important','Normal'].includes(row.priority)){let p=row.priority.toLowerCase();if(['high','critical'].includes(p))row.priority='Urgent';else if(['medium','moderate'].includes(p))row.priority='Important';else if(['low'].includes(p))row.priority='Normal';else{warn.push('Unknown priority; set to Normal');row.priority='Normal'}}if(Number.isNaN(row.progress)||row.progress<0||row.progress>100||![0,25,50,75,100].includes(row.progress))errs.push('Progress must be 0, 25, 50, 75 or 100');if(row.startDate===null)errs.push('Invalid start date');if(row.deadline===null)errs.push('Invalid deadline');if(row.startDate&&row.deadline&&row.startDate>row.deadline)errs.push('Start date must be on or before deadline');if(!get('startDate'))row.startDate='';if(!get('deadline'))row.deadline='';if(!row.deadline)warn.push('No deadline');let dup=findDuplicate(row);if(dup)warn.push('Possible duplicate: '+dup.name);if(errs.length)errors++;else{valid++;if(warn.length)warnings++}return {row,errs,warn,dup,index:i+2}});document.getElementById('importSummary').innerHTML=`<b>${valid} valid</b> · <span class="warn">${warnings} with warnings</span> · <span class="bad">${errors} errors</span> · ${importRows.length} rows detected`;document.getElementById('previewTable').innerHTML=`<table><thead><tr><th>Excel row</th><th>Task</th><th>Priority</th><th>Progress</th><th>Validation</th></tr></thead><tbody>${importValidation.map(v=>`<tr><td>${v.index}</td><td>${esc(v.row.name||'—')}</td><td>${esc(v.row.priority)}</td><td>${Number.isNaN(v.row.progress)?'—':v.row.progress+'%'}</td><td class="status ${v.errs.length?'bad':v.warn.length?'warn':'good'}">${v.errs.length?esc(v.errs.join('; ')):v.warn.length?esc(v.warn.join('; ')):'Valid'}</td></tr>`).join('')}</tbody></table>`;document.getElementById('confirmImport').disabled=valid===0}
document.getElementById('confirmImport').onclick=()=>{let mode=document.getElementById('duplicateMode').value,added=0,updated=0,skipped=0,failed=0;importValidation.forEach(v=>{if(v.errs.length){failed++;return}let r=v.row,dup=findDuplicate(r);if(dup&&mode==='skip'){skipped++;return}let refs=r.refs?r.refs.split(/[;\n]/).map(s=>s.trim()).filter(Boolean).map(url=>({url})):[];let problems=dup?.problems||[];if(r.problem)problems=[{id:id(),title:r.problem,severity:'Medium',reporter:'Imported from Excel',details:'',resolved:false},...problems];let obj={id:dup&&mode==='update'?dup.id:id(),taskId:r.taskId,name:r.name,brand:r.brand,priority:r.priority,type:r.type,owner:r.owner,startDate:r.startDate,deadline:r.deadline,progress:r.progress,notes:r.notes,refs,problems,order:dup&&mode==='update'?dup.order:undefined};if(dup&&mode==='update'){tasks=tasks.map(t=>t.id===dup.id?obj:t);updated++}else{tasks.unshift(obj);added++}});save();hide('importModal');render();alert(`Import finished.\nAdded: ${added}\nUpdated: ${updated}\nSkipped duplicates: ${skipped}\nRows with errors: ${failed}`)};
document.getElementById('templateBtn').onclick=()=>{if(!window.XLSX){alert('Template download needs an internet connection.');return}let sample=[{'Task ID':'TASK-001','Task Name':'Design campaign artwork','Brand':'CED','Priority':'Urgent','Type':'Digital','Assigned To':'Marketing Team','Start Date':'2026-11-04','Deadline':'2026-11-10','Progress':50,'Problem':'Waiting for product photos','References':'https://example.com/brief','Notes':'First draft for review'}];let wb=XLSX.utils.book_new();XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(sample),'Tasks');XLSX.writeFile(wb,'team-project-template.xlsx')};
function chartEmpty(msg='Add tasks to see this diagram.') { return `<div class="chart-empty">${msg}</div>`; }
function renderAnalytics(){
 const total=tasks.length,avg=total?Math.round(tasks.reduce((a,t)=>a+(Number(t.progress)||0),0)/total):0;
 const done=tasks.filter(t=>Number(t.progress)===100).length,doing=tasks.filter(t=>Number(t.progress)>0&&Number(t.progress)<100).length,not=tasks.filter(t=>Number(t.progress)===0).length;
 const pct=n=>total?Math.round(n/total*100):0;
 const statusColors=['#16a36a','#4169e1','#eab308'];
 const segments=[{label:'Completed',n:done,color:statusColors[0],filter:'100'},{label:'In progress',n:doing,color:statusColors[1],filter:'inprogress'},{label:'Not started',n:not,color:statusColors[2],filter:'0'}];
 let angle=0,stops=segments.map(x=>{let start=angle;angle+=pct(x.n)*3.6;return `${x.color} ${start}deg ${angle}deg`}).join(',');
 document.getElementById('progressChart').innerHTML=total?`<div class="donut-wrap"><div class="donut" style="background:conic-gradient(${stops||'var(--line) 0deg 360deg'})"><div class="donut-center"><b>${avg}%</b><span>AVERAGE</span></div></div><div class="legend">${segments.map(x=>`<button onclick="chartStatus('${x.filter}')"><i class="dot" style="background:${x.color}"></i>${x.label}<b style="margin-left:auto">${x.n}</b></button>`).join('')}<span class="small">${total} total tasks</span></div></div>`:chartEmpty();
 document.getElementById('statusChart').innerHTML=total?`<div class="chart-bars">${segments.map(x=>`<button class="bar-row" onclick="chartStatus('${x.filter}')"><span class="bar-label">${x.label}</span><span class="bar-track"><span class="bar-fill" style="display:block;width:${pct(x.n)}%;background:${x.color}"></span></span><b>${x.n}</b></button>`).join('')}</div>`:chartEmpty();
 const priorities=[{label:'Urgent',color:'#df4b55'},{label:'Important',color:'#d69a27'},{label:'Normal',color:'#4169e1'}].map(x=>({...x,n:tasks.filter(t=>t.priority===x.label).length}));const maxP=Math.max(1,...priorities.map(x=>x.n));
 document.getElementById('priorityChart').innerHTML=total?`<div class="chart-bars">${priorities.map(x=>`<button class="bar-row" onclick="chartPriority('${x.label}')"><span class="bar-label">${x.label}</span><span class="bar-track"><span class="bar-fill" style="display:block;width:${x.n/maxP*100}%;background:${x.color}"></span></span><b>${x.n}</b></button>`).join('')}</div>`:chartEmpty();
 const allProblems=tasks.flatMap(t=>(t.problems||[]).map(p=>({...p,taskName:t.name,taskRef:t.id})));const open=allProblems.filter(p=>!p.resolved),resolved=allProblems.filter(p=>p.resolved);const sev=['High','Medium','Low'].map((s,i)=>({label:s,color:['#df4b55','#d69a27','#4169e1'][i],open:open.filter(p=>p.severity===s).length,resolved:resolved.filter(p=>p.severity===s).length}));const maxIssue=Math.max(1,...sev.map(x=>x.open+x.resolved));
 document.getElementById('problemChart').innerHTML=allProblems.length?`<div class="chart-bars">${sev.map(x=>`<button type="button" class="bar-row" title="Show ${x.label} severity tasks" onclick="chartSeverity('${x.label}')"><span class="bar-label">${x.label}</span><span class="bar-track" style="display:flex"><span class="bar-fill" style="width:${x.open/maxIssue*100}%;background:${x.color};border-radius:20px 0 0 20px"></span><span class="bar-fill" style="width:${x.resolved/maxIssue*100}%;background:#cbd5e1;border-radius:0 20px 20px 0"></span></span><b>${x.open+x.resolved}</b></button>`).join('')}</div><div class="legend" style="display:flex;gap:14px;margin-top:13px"><span><i class="dot" style="background:#df4b55"></i> Open</span><span><i class="dot" style="background:#cbd5e1"></i> Resolved</span></div><div class="chart-foot">${open.length} open · ${resolved.length} resolved · ${allProblems.length} total</div>`:chartEmpty('No problem reports yet.');
 const owners={};tasks.forEach(t=>{let name=(t.owner||'Unassigned').trim()||'Unassigned';owners[name]??={total:0,done:0};owners[name].total++;if(Number(t.progress)===100)owners[name].done++});const people=Object.entries(owners).sort((a,b)=>b[1].done-a[1].done||b[1].total-a[1].total).slice(0,8);const maxTeam=Math.max(1,...people.map(x=>x[1].total));
 document.getElementById('teamChart').innerHTML=people.length?`<div class="chart-bars">${people.map(([name,v])=>`<button class="bar-row" style="grid-template-columns:90px minmax(40px,1fr) 42px" onclick="chartOwner('${esc(name).replace(/'/g,"\\'")}')"><span class="bar-label" title="${esc(name)}">${esc(name.length>15?name.slice(0,14)+'…':name)}</span><span class="bar-track" style="display:flex"><span class="bar-fill" style="width:${v.done/maxTeam*100}%;background:#16a36a;border-radius:20px 0 0 20px"></span><span class="bar-fill" style="width:${(v.total-v.done)/maxTeam*100}%;background:#a5b4fc;border-radius:0 20px 20px 0"></span></span><b>${v.done}/${v.total}</b></button>`).join('')}</div><div class="chart-foot">Completed / assigned tasks · Select a member to filter</div>`:chartEmpty();
 const bmap={};BRANDS.forEach(b=>bmap[b]={p:0,n:0,d:0});let noBrand={p:0,n:0,d:0};tasks.forEach(t=>{const o=bmap[t.brand]||noBrand,g=Number(t.progress)||0;if(g>=100)o.d++;else if(g>0)o.p++;else o.n++});
 const brows=BRANDS.filter(b=>!lockBrand()||b===lockBrand()).map(b=>({name:b,...bmap[b]}));if(noBrand.p+noBrand.n+noBrand.d)brows.push({name:'No brand',...noBrand});
 const bcell=(v,c)=>v?`<td class="${c}"><b>${v}</b></td>`:'<td class="z">0</td>';
 document.getElementById('brandChart').innerHTML=total?`<div class="brand-scroll"><table class="brand-table"><thead><tr><th>Brand</th><th>In Progress</th><th>Not Started</th><th>Completed</th></tr></thead><tbody>${brows.map(r=>`<tr onclick="chartBrand('${esc(r.name).replace(/'/g,"\\'")}')"><td><span class="brand-name"><i></i>${esc(r.name)}</span></td>${bcell(r.p,'c-prog')}${bcell(r.n,'c-not')}${bcell(r.d,'c-done')}</tr>`).join('')}</tbody></table></div><div class="chart-foot">In progress / not started / completed tasks per brand</div>`:chartEmpty();
 const dated=tasks.filter(t=>t.startDate&&t.deadline&&t.startDate<=t.deadline).sort((a,b)=>a.startDate.localeCompare(b.startDate)).slice(0,12);if(!dated.length){document.getElementById('ganttChart').innerHTML=chartEmpty('Add a start date and deadline to tasks to display the timeline.');return}
 const min=Math.min(...dated.map(t=>new Date(t.startDate+'T00:00:00').getTime())),max=Math.max(...dated.map(t=>new Date(t.deadline+'T00:00:00').getTime())),span=Math.max(86400000,max-min);
 document.getElementById('ganttChart').innerHTML=`<div class="timeline">${dated.map(t=>{let a=new Date(t.startDate+'T00:00:00').getTime(),b=new Date(t.deadline+'T00:00:00').getTime(),left=(a-min)/span*100,width=Math.max(1,(b-a)/span*100),color=t.progress===100?'#16a36a':t.progress>0?'#4169e1':'#cbd5e1';return `<button class="timeline-row" onclick="editTask('${t.id}')"><span class="timeline-name" title="${esc(t.name)}">${esc(t.name)}</span><span class="timeline-track"><span class="timeline-bar" style="left:${left}%;width:${width}%;background:${color}"></span></span><span>${esc(t.deadline)}</span></button>`}).join('')}</div><div class="chart-foot">Showing up to 12 scheduled tasks · Green = completed, blue = in progress, grey = not started</div>`;
}
function chartStatus(v){document.getElementById('priorityFilter').value='';document.getElementById('typeFilter').value='';document.getElementById('brandFilter').value='';document.getElementById('statusFilter').value=v;document.getElementById('search').value='';render();document.getElementById('taskList').scrollIntoView({behavior:'smooth',block:'start'})}
function chartBrand(v){document.getElementById('priorityFilter').value='';document.getElementById('typeFilter').value='';document.getElementById('statusFilter').value='';document.getElementById('search').value='';document.getElementById('brandFilter').value=BRANDS.includes(v)?v:'';render();document.getElementById('taskList').scrollIntoView({behavior:'smooth',block:'start'})}
function chartPriority(v){document.getElementById('priorityFilter').value=v;document.getElementById('typeFilter').value='';document.getElementById('brandFilter').value='';document.getElementById('statusFilter').value='';document.getElementById('search').value='';render();document.getElementById('taskList').scrollIntoView({behavior:'smooth',block:'start'})}
function chartOwner(v){document.getElementById('priorityFilter').value='';document.getElementById('typeFilter').value='';document.getElementById('brandFilter').value='';document.getElementById('statusFilter').value='';document.getElementById('search').value=v==='Unassigned'?'':v;render();document.getElementById('taskList').scrollIntoView({behavior:'smooth',block:'start'})}
document.getElementById('clearChartFilters').onclick=()=>{document.getElementById('priorityFilter').value='';document.getElementById('typeFilter').value='';document.getElementById('brandFilter').value='';document.getElementById('statusFilter').value='';document.getElementById('search').value='';render()};
// Refresh diagrams whenever tasks are rendered or changed.
const originalRender=render;render=function(){originalRender();renderAnalytics();if(window.calendarRender&&!document.getElementById('calendarHost').hidden)calendarRender()};
render();

// Calendar view (same page, switched by #calendar)
const calHost=document.getElementById('calendarHost');
calHost.attachShadow({mode:'open'}).appendChild(document.getElementById('calendarTemplate').content.cloneNode(true));
(function(){
const root=document.getElementById('calendarHost').shadowRoot;
let cur=new Date(),mode='month';
try{const m=sessionStorage.getItem('calMode');if(['week','month','quarter'].includes(m))mode=m}catch{}
const MONTHS=['January','February','March','April','May','June','July','August','September','October','November','December'];
const DOWS=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
root.getElementById('dows').innerHTML=DOWS.map(d=>`<div class="dow">${d}</div>`).join('');
function esc(s=''){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function pad(n){return String(n).padStart(2,'0')}
function keyOf(d){return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())}
function dateKey(v){if(!v)return'';let s=String(v).trim(),m=s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);if(m)return m[1]+'-'+pad(m[2])+'-'+pad(m[3]);let d=new Date(s);return isNaN(d)?'':keyOf(d)}
function prio(t){let p=String(t.priority||'').toLowerCase();return p.includes('urgent')?'urgent':p.includes('important')||p.includes('high')?'important':'normal'}
function isDone(t){return Number(t.progress)>=100}
function cls(t){return isDone(t)?'done':prio(t)}
// Manager View: only the selected brand's projects are ever shown here (also while paging months/weeks).
function activeBrand(){if(typeof lockBrand==='function'&&lockBrand())return lockBrand();try{if(sessionStorage.getItem('mgrAuthed')==='1')return sessionStorage.getItem('mgrBrand')||''}catch{}return ''}
function visible(){if(typeof lockBrand==='function'&&lockBrand()&&typeof scopedTasks==='function')return scopedTasks();const b=activeBrand();return b?tasks.filter(t=>t.brand===b):tasks}
let byDay={};
function cell(d,o){
  const k=keyOf(d),list=byDay[k]||[],todayK=keyOf(new Date());
  const c=['day',o.out?'out':'',k===todayK?'today':'',list.length?'has':'',o.col<2?'edge-l':'',o.col>4?'edge-r':'',o.low?'low':''].filter(Boolean).join(' ');
  const chips=list.slice(0,o.max).map(t=>`<span class="chip ${cls(t)}" data-id="${esc(t.id)}" role="button" tabindex="0">${esc(t.name||'Untitled')}</span>`).join('')+(list.length>o.max?`<div class="more">+${list.length-o.max} more</div>`:'');
  const pop=list.length?`<div class="pop" role="tooltip"><h4>${d.toLocaleDateString(undefined,{weekday:'long',month:'long',day:'numeric',year:'numeric'})} <small>· ${list.length} project${list.length>1?'s':''} due</small></h4>${list.map(t=>{const p=Math.max(0,Math.min(100,Number(t.progress)||0)),over=!isDone(t)&&k<todayK;return `<div class="pi" data-id="${esc(t.id)}" role="button" tabindex="0"><b>${esc(t.name||'Untitled')}</b><div class="m"><span>${esc(t.owner||'Unassigned')}</span>${t.brand?`<span class="tag">${esc(t.brand)}</span>`:''}${t.type?`<span class="tag">${esc(t.type)}</span>`:''}<span class="tag ${prio(t)}">${esc(t.priority||'Normal')}</span>${over?'<span class="tag overdue">Overdue</span>':''}<span>${p}%${isDone(t)?' · Completed':''}</span></div><div class="bar"><i style="width:${p}%"></i></div></div>`}).join('')}</div>`:'';
  const mon=o.showMon?`<span class="mon">${d.toLocaleDateString(undefined,{month:'short'})}</span>`:'';
  return `<div class="${c}"${list.length?' tabindex="0"':''}><span class="num">${d.getDate()}</span>${mon}${list.length?`<span class="count">${list.length}</span>`:''}${chips}${pop}</div>`;
}
function render(){
  const y=cur.getFullYear(),mo=cur.getMonth(),todayK=keyOf(new Date());
  byDay={};visible().forEach(t=>{let k=dateKey(t.deadline);if(k)(byDay[k]=byDay[k]||[]).push(t)});
  Object.values(byDay).forEach(l=>l.sort((a,b)=>isDone(a)-isDone(b)||['urgent','important','normal'].indexOf(prio(a))-['urgent','important','normal'].indexOf(prio(b))));
  const daysEl=root.getElementById('days'),dowsEl=root.getElementById('dows');
  let html='',inRange=[],label='',unit='';
  if(mode==='week'){
    const s=new Date(y,mo,cur.getDate()-cur.getDay()),e=new Date(s.getFullYear(),s.getMonth(),s.getDate()+6);
    for(let i=0;i<7;i++){const d=new Date(s.getFullYear(),s.getMonth(),s.getDate()+i);inRange.push(...(byDay[keyOf(d)]||[]));html+=cell(d,{col:i,max:99,showMon:i===0||d.getDate()===1})}
    const f=(d,yr)=>d.toLocaleDateString(undefined,yr?{month:'short',day:'numeric',year:'numeric'}:{month:'short',day:'numeric'});
    label=f(s,s.getFullYear()!==e.getFullYear())+' – '+f(e,true);unit='this week';
    daysEl.className='grid week';dowsEl.style.display='';
  }else if(mode==='quarter'){
    const q0=Math.floor(mo/3)*3;
    for(let m=0;m<3;m++){
      const lead=new Date(y,q0+m,1).getDay(),dim=new Date(y,q0+m+1,0).getDate(),weeks=Math.ceil((lead+dim)/7);let cells='';
      for(let i=0;i<weeks*7;i++){const dn=i-lead+1;if(dn<1||dn>dim){cells+='<div class="day blank"></div>';continue}const d=new Date(y,q0+m,dn);inRange.push(...(byDay[keyOf(d)]||[]));cells+=cell(d,{col:i%7,max:0,low:Math.floor(i/7)>=weeks-2&&weeks>3})}
      html+=`<div class="qmonth"><h3>${MONTHS[(q0+m)%12]}</h3><div class="grid">${DOWS.map(d=>`<div class="dow">${d.slice(0,2)}</div>`).join('')}</div><div class="grid" style="margin-top:4px">${cells}</div></div>`;
    }
    label='Q'+(q0/3+1)+' '+y+' · '+MONTHS[q0].slice(0,3)+' – '+MONTHS[q0+2].slice(0,3);unit='this quarter';
    daysEl.className='qwrap';dowsEl.style.display='none';
  }else{
    const start=new Date(y,mo,1-new Date(y,mo,1).getDay()),weeks=Math.ceil((new Date(y,mo,1).getDay()+new Date(y,mo+1,0).getDate())/7);
    for(let i=0;i<weeks*7;i++){
      const d=new Date(start.getFullYear(),start.getMonth(),start.getDate()+i),inMonth=d.getMonth()===mo;
      if(inMonth)inRange.push(...(byDay[keyOf(d)]||[]));
      html+=cell(d,{col:i%7,max:3,out:!inMonth,low:Math.floor(i/7)>=weeks-2&&weeks>3});
    }
    label=MONTHS[mo]+' '+y;unit='this month';
    daysEl.className='grid';dowsEl.style.display='';
  }
  daysEl.innerHTML=html;
  root.getElementById('monthLabel').textContent=label;
  root.querySelectorAll('#seg button').forEach(b=>b.classList.toggle('on',b.dataset.v===mode));
  const done=inRange.filter(isDone).length,over=inRange.filter(t=>!isDone(t)&&dateKey(t.deadline)<todayK).length,b=activeBrand();
  root.getElementById('monthSummary').textContent=(b?b+' · ':'')+(inRange.length?`${inRange.length} project deadline${inRange.length>1?'s':''} ${unit} · ${done} completed${over?` · ${over} overdue`:''}`:`No project deadlines ${unit}`);
}
function step(n){
  const y=cur.getFullYear(),mo=cur.getMonth();
  if(mode==='week')cur=new Date(y,mo,cur.getDate()+7*n);
  else if(mode==='quarter')cur=new Date(y,mo+3*n,1);
  else cur=new Date(y,mo+n,1);
  render();
}
root.getElementById('prev').onclick=()=>step(-1);
root.getElementById('next').onclick=()=>step(1);
root.getElementById('todayBtn').onclick=()=>{cur=new Date();render()};
root.querySelectorAll('#seg button').forEach(b=>b.onclick=()=>{mode=b.dataset.v;try{sessionStorage.setItem('calMode',mode)}catch{}render()});
root.addEventListener('click',e=>{const el=e.target.closest('.chip[data-id],.pi[data-id]');if(el&&window.dzOpenDetail){e.stopPropagation();window.dzOpenDetail(el.dataset.id)}});
root.addEventListener('keydown',e=>{if(e.key!=='Enter'&&e.key!==' ')return;const el=e.target.closest&&e.target.closest('.chip[data-id],.pi[data-id]');if(el&&window.dzOpenDetail){e.preventDefault();window.dzOpenDetail(el.dataset.id)}});
window.calendarRender=render;
})();
const TRACKER_TITLE=document.title;
function route(){const cal=location.hash==='#calendar';document.getElementById('trackerView').style.display=cal?'none':'';calHost.hidden=!cal;document.title=cal?'Deadline Calendar \u00b7 Team Project Tracker':TRACKER_TITLE;if(cal)calendarRender();window.scrollTo(0,0)}
window.addEventListener('hashchange',route);route();

// ===== Manager View =====
// NOTE: like the team login above, this check runs in the browser and can be read in the page source.
const MGR_USER='Kinal Kong',MGR_HASH='1664ea274d8f69a2793b68eb3b820878b20bf2bb3893e1c721592c12fba89c77';
let mgrAuthed=sessionStorage.getItem('mgrAuthed')==='1',mgrBrand=null;
try{let sv=sessionStorage.getItem('mgrBrand');if(mgrAuthed&&BRANDS.includes(sv))mgrBrand=sv}catch{}
const mgrEl=i=>document.getElementById(i);
function mgrStep(x){['Login','Brand'].forEach(k=>mgrEl('mgrStep'+k).hidden=k!==x)}
function mgrShowBrands(){mgrEl('mgrBrands').innerHTML=BRANDS.map(b=>{const n=tasks.filter(t=>t.brand===b).length;return `<button class="btn-light" data-brand="${esc(b)}">${esc(b)}<small>${n} project${n===1?'':'s'} ›</small></button>`}).join('');mgrStep('Brand')}
function mgrOpen(){if(lockBrand())return;mgrEl('mgrError').style.display='none';mgrEl('mgrLoginForm').reset();if(!mgrAuthed)mgrStep('Login');else mgrShowBrands();show('managerModal')}
function mgrApply(){const on=!!mgrBrand;document.body.classList.toggle('manager-mode',on);if(on){mgrEl('mgrTrail').textContent='Brand: '+mgrBrand;sessionStorage.setItem('mgrBrand',mgrBrand)}else sessionStorage.removeItem('mgrBrand');render()}
mgrEl('managerBtn').onclick=mgrOpen;
mgrEl('mgrLoginForm').addEventListener('submit',e=>{e.preventDefault();if(mgrEl('mgrUser').value.trim().toLowerCase()===MGR_USER.toLowerCase()&&sha256('tracker:'+MGR_USER.toLowerCase()+':'+mgrEl('mgrPass').value)===MGR_HASH){mgrAuthed=true;sessionStorage.setItem('mgrAuthed','1');mgrShowBrands()}else{mgrEl('mgrError').style.display='block'}});
mgrEl('mgrBrands').addEventListener('click',e=>{const b=e.target.closest('[data-brand]');if(b){mgrBrand=b.dataset.brand;hide('managerModal');['priorityFilter','brandFilter','typeFilter','statusFilter','search'].forEach(i=>mgrEl(i).value='');mgrApply();window.scrollTo(0,0)}});
mgrEl('mgrChange').onclick=()=>{mgrShowBrands();show('managerModal')};
mgrEl('mgrExit').onclick=()=>{mgrBrand=null;mgrApply()};
// Show only the selected brand's projects everywhere (stats, charts, list, calendar) without touching saved data.
const baseRender=render;
render=function(){if(!ACTIVE){const all0=tasks;tasks=[];try{baseRender()}finally{tasks=all0}return}const scope=lockBrand()||mgrBrand;if(!scope){baseRender();return}const all=tasks;tasks=lockBrand()?scopedTasks():all.filter(t=>t.brand===scope);try{baseRender();mgrEl('mgrCount').textContent=tasks.length+' project'+(tasks.length===1?'':'s')}finally{tasks=all}};
if(mgrBrand)mgrApply();

// ===== Apply the signed-in account =====
const _openTask=openTask;
openTask=function(t){_openTask(t);const sel=document.getElementById('taskBrand'),b=lockBrand();if(b){sel.value=b;sel.disabled=true}else sel.disabled=false;dzReqSetup(t)};
function applyAccount(){
  if(!ACTIVE)return;
  const b=lockBrand();
  document.body.classList.toggle('brand-user',!!b);
  if(ACTIVE.role==='manager'){mgrAuthed=true;try{sessionStorage.setItem('mgrAuthed','1')}catch(e){}}
  else{mgrAuthed=false;mgrBrand=null;document.body.classList.remove('manager-mode');try{sessionStorage.removeItem('mgrAuthed');sessionStorage.removeItem('mgrBrand')}catch(e){}}
  dzSetup(b==='Designer');
  const sub=document.querySelector('header.top .sub');
  if(sub)sub.textContent='Signed in as '+ACTIVE.user+' · '+(b==='Designer'&&ACTIVE.dzName?'Designer ('+ACTIVE.dzName+')':b?b+' brand':'All brands');
  ['priorityFilter','brandFilter','typeFilter','statusFilter','search'].forEach(i=>{const el=document.getElementById(i);if(el)el.value=''});
  render();
}
// ===== Designer workspace: board by design stage =====
['Poster','Social post','Banner','Packaging','Video','Illustration'].forEach(x=>{TYPES.push(x);['taskType','typeFilter'].forEach(id=>{const o=document.createElement('option');o.textContent=x;document.getElementById(id).appendChild(o)})});
const DZ_STAGES=[[0,'Brief received'],[25,'Designing'],[50,'In review'],[75,'Revision'],[100,'Delivered']];
function dzMove(i,d){const t=tasks.find(x=>x.id===i);if(t){t.dzNew=false;dzStamp(t);setProgress(i,Math.max(0,Math.min(100,t.progress+d)))}}
function dzSetup(on){document.body.classList.toggle('designer-ui',on);if(!on)return;
  const set=(q,t)=>{const e=document.querySelector(q);if(e)e.textContent=t};
  set('#totalTaskCard .label','ALL DESIGN REQUESTS');set('#completedTaskCard .label','DELIVERED');set('#inProgressTaskCard .label','IN DESIGN');set('#tasksPage .panel-head h2','Design board');
  const g=document.querySelector('#tasksPage .side .panel:last-child .small');if(g)g.innerHTML='• Drag a card with your mouse to any stage.<br>• ✓ Done sends a card to Archived.<br>• Remove sends a card to Archived as Removed.<br>• Past-deadline cards go to Archived as Missed.<br>• Brief → Designing → Review → Revision → Delivered.<br>• Attach design files under Files.<br>• Overdue requests have a red border.'}
function dzBoard(){
  const v=i=>document.getElementById(i).value,q=v('search').toLowerCase(),pf=v('priorityFilter'),tf=v('typeFilter'),sf=v('statusFilter'),today=(d=>d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'))(new Date());
  const list=scopedTasks().filter(t=>(!q||(t.name+' '+(t.owner||'')+' '+(t.notes||'')).toLowerCase().includes(q))&&(!pf||t.priority===pf)&&(!tf||t.type===tf)&&(sf===''||(sf==='inprogress'?(t.progress>0&&t.progress<100):String(t.progress)===sf)));
  const card=t=>`<article class="dz-card ${t.deadline&&t.deadline<today&&t.progress<100?'late':''}" data-id="${t.id}"><div class="dz-top"><b>${esc(t.name)}${t.dzNew?' <span class="pill urgent">NEW</span>':''}</b><span class="pill ${t.priority.toLowerCase()}">${esc(t.priority)}</span></div><div class="meta">${typePill(t)} ${esc(t.owner||'Unassigned')}</div><div class="meta">Due ${dateFmt(t.deadline)}</div>${dzEdited(t)}<div class="dz-acts"><button class="text-btn" onclick="editTask('${t.id}')">Edit</button><button class="text-btn" onclick="showRefs('${t.id}')">Files (${(t.refs||[]).length})</button><button class="text-btn dz-done" onclick="dzDone('${t.id}')">✓ Done</button><button class="text-btn dz-del" onclick="dzRemove('${t.id}')">Remove</button></div></article>`;
  const active=list.filter(t=>!dzArchState(t,today)),arch=list.filter(t=>dzArchState(t,today));
  document.getElementById('taskList').innerHTML='<div class="dz-board">'+DZ_STAGES.map(([p,l])=>{const c=active.filter(t=>t.progress===p);return `<div class="dz-col"><h4>${l} <span>${c.length}</span></h4>${c.map(card).join('')||'<div class="dz-empty">—</div>'}</div>`}).join('')+'</div>';
  dzArchiveRender()}
function dzArchState(t,today){if(t.archived==='done')return 'done';if(t.archived==='removed')return 'removed';if(t.deadline&&t.deadline<today&&Number(t.progress)<100)return 'missed';return ''}
var dzArchFilter='all';
function dzEdited(t){if(!t.editedAt)return '';const e=new Date(t.editedAt);if(isNaN(e))return '';const n=new Date(),two=x=>String(x).padStart(2,'0');let txt;
  if(e.toDateString()===n.toDateString()){txt=(e.getHours()%12||12)+':'+two(e.getMinutes())+' '+(e.getHours()<12?'AM':'PM')}
  else{txt=two(e.getDate())+'/'+two(e.getMonth()+1);if(e.getFullYear()!==n.getFullYear())txt+='/'+e.getFullYear()}
  return `<div class="meta dz-edited" title="${esc(e.toLocaleString())}">✎ Edited ${txt}</div>`}
function dzStamp(t){t.editedAt=new Date().toISOString()}
function dzToday(){const d=new Date();return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')}
function dzACard(t,today){const st=dzArchState(t,today);return `<article class="dz-acard ${st}" data-id="${t.id}"><div class="dz-top"><b>${esc(t.name)}</b><span class="pill dz-st-${st}">${st==='done'?'✓ Done':st==='removed'?'🗑 Removed':'⚠ Missed'}</span></div><div class="meta">${typePill(t)} ${esc(t.owner||'Unassigned')}</div><div class="meta">${st==='missed'?'Deadline passed · ':st==='removed'?'Removed · ':''}Due ${dateFmt(t.deadline)}</div>${dzEdited(t)}<div class="dz-acts"><button class="text-btn" onclick="editTask('${t.id}')">Edit</button><button class="text-btn" onclick="showRefs('${t.id}')">Files (${(t.refs||[]).length})</button>${st!=='missed'?`<button class="text-btn" onclick="dzRestore('${t.id}')">↩ Restore</button>`:''}<button class="text-btn dz-del" onclick="deleteTask('${t.id}')">Delete forever</button></div></article>`}
function dzSetArch(k){dzArchFilter=k;dzArchiveRender()}
function dzArchiveRender(){
  const grid=document.getElementById('archiveList');if(!grid)return;
  const today=dzToday(),q=(document.getElementById('archSearch').value||'').toLowerCase();
  const all=(lockBrand()==='Designer'?scopedTasks():[]).filter(t=>dzArchState(t,today));
  const cnt=k=>all.filter(t=>dzArchState(t,today)===k).length,nDone=cnt('done'),nMiss=cnt('missed'),nRem=cnt('removed');
  const shown=all.filter(t=>(dzArchFilter==='all'||dzArchState(t,today)===dzArchFilter)&&(!q||(t.name+' '+(t.owner||'')+' '+(t.notes||'')).toLowerCase().includes(q)));
  const chip=(k,l,n)=>`<button type="button" class="dz-chip ${dzArchFilter===k?'on':''}" onclick="dzSetArch('${k}')">${l} <span>${n}</span></button>`;
  document.getElementById('archChips').innerHTML=chip('all','All',all.length)+chip('done','Done',nDone)+chip('missed','Missed',nMiss)+chip('removed','Removed',nRem);
  grid.innerHTML=shown.map(t=>dzACard(t,today)).join('')||'<div class="dz-empty">Nothing archived yet.</div>';
  const bc=document.getElementById('archivedCount');if(bc)bc.textContent=all.length?'('+all.length+')':'';
  if(window.dzArchSync)window.dzArchSync()}
function dzDone(i){const t=tasks.find(x=>x.id===i);if(!t)return;t.dzNew=false;t.progress=100;t.archived='done';dzStamp(t);t.archivedAt=new Date().toISOString();save();render()}
function dzRemove(i){const t=tasks.find(x=>x.id===i);if(!t)return;t.dzNew=false;t.archived='removed';dzStamp(t);t.archivedAt=new Date().toISOString();save();render()}
function dzRestore(i){const t=tasks.find(x=>x.id===i);if(!t)return;delete t.archived;delete t.archivedAt;dzStamp(t);save();render()}
function dzReqSetup(t){const row=document.getElementById('dzReqRow'),cb=document.getElementById('taskDzReq');cb.checked=false;row.style.display=(lockBrand()==='Designer'||t?.designerRequested||t?.brand==='Designer')?'none':''}
function dzMaybeRequest(obj){
  if(!document.getElementById('taskDzReq').checked||obj.designerRequested||lockBrand()==='Designer'||obj.brand==='Designer'||!obj.brand)return;
  obj.designerRequested=true;
  tasks.unshift({id:id(),name:'['+obj.brand+'] '+obj.name,brand:'Designer',priority:obj.priority,type:'',owner:'Requested by '+obj.brand,designer:dzDesignerFor(obj.brand),startDate:obj.startDate,deadline:obj.deadline,progress:0,notes:'',brief:Object.assign({},window.dzPendingBrief||{}),refs:[],problems:[],taskId:'',fromTask:obj.id,requestedBy:obj.brand,dzNew:true});
  {const dn=dzDesignerFor(obj.brand);alert(dn?'Request sent and auto-assigned to '+dn+'.':'Designer has been alerted about this request.')}}
const dzBar=document.createElement('div');dzBar.id='dzAlert';document.body.appendChild(dzBar);
function dzAlertUpdate(){
  const f=lockBrand()==='Designer'?scopedTasks().filter(t=>t.dzNew):[],base=document.title.replace(/^\(\d+\) /,'');
  if(!f.length){dzBar.style.display='none';document.title=base;return}
  document.title='('+f.length+') '+base;
  dzBar.innerHTML='<span>🔔 <b>'+f.length+' new design request'+(f.length>1?'s':'')+'</b> · '+esc(f.slice(0,2).map(t=>t.name).join(', '))+(f.length>2?'…':'')+'</span><button class="btn-light" id="dzView">View board</button><button class="btn-light" id="dzSeen">Mark seen</button>';
  dzBar.style.display='flex';
  document.getElementById('dzView').onclick=()=>{location.hash='tasks'};
  document.getElementById('dzSeen').onclick=()=>{f.forEach(t=>t.dzNew=false);save();render()}}
const _rDz=render;render=function(){_rDz();if(lockBrand()==='Designer')dzBoard();dzAlertUpdate()};
if(ACTIVE)applyAccount();else render();
;

/* ===== Script 2 ===== */
(function(){
var KEY='cm-theme',html=document.documentElement,host=document.getElementById('calendarHost');
function cur(){return html.getAttribute('data-theme')==='light'?'light':'dark'}
function paint(){
  var t=cur(),label=t==='dark'?'\u2600\ufe0f Light mode':'\ud83c\udf19 Dark mode';
  if(host)host.setAttribute('data-theme',t);
  document.querySelectorAll('.theme-toggle').forEach(function(b){b.textContent=label});
  if(host&&host.shadowRoot)host.shadowRoot.querySelectorAll('.theme-toggle').forEach(function(b){b.textContent=label});
}
function toggle(e){if(e.target.closest&&e.target.closest('.theme-toggle')){var t=cur()==='dark'?'light':'dark';html.setAttribute('data-theme',t);try{localStorage.setItem(KEY,t)}catch(x){}paint()}}
document.addEventListener('click',toggle);
if(host&&host.shadowRoot)host.shadowRoot.addEventListener('click',toggle);
paint();
})();
;

/* ===== Script 3 ===== */
// Drag & drop reordering of project cards (mouse, touch and keyboard)
(function(){
const list=document.getElementById('taskList');
let d=null,raf=0;
function clearMarks(){list.querySelectorAll('.drop-before,.drop-after').forEach(c=>c.classList.remove('drop-before','drop-after'))}
function place(id,targetId,after){
  const from=tasks.findIndex(t=>t.id===id);if(from<0||id===targetId)return false;
  const item=tasks.splice(from,1)[0];let to=tasks.findIndex(t=>t.id===targetId);
  if(to<0){tasks.splice(from,0,item);return false}
  tasks.splice(after?to+1:to,0,item);
  tasks.forEach((t,i)=>{if(t.order!==i)t.order=i});
  save();render();return true;
}
function update(){
  if(!d)return;
  const dy=(d.y-d.startY)+(window.scrollY-d.startScroll);
  d.card.style.transform='translateY('+dy+'px)';
  clearMarks();d.target=null;
  const cards=[...list.querySelectorAll('.task')].filter(c=>c!==d.card);
  for(const c of cards){const r=c.getBoundingClientRect();d.target=c;d.after=true;if(d.y<r.top+r.height/2){d.after=false;break}}
  if(d.target)d.target.classList.add(d.after?'drop-after':'drop-before');
}
function loop(){
  if(!d)return;
  const edge=70;let v=0;
  if(d.y<edge)v=-Math.ceil((edge-d.y)/5);else if(d.y>innerHeight-edge)v=Math.ceil((d.y-(innerHeight-edge))/5);
  if(v){scrollBy(0,v);update()}
  raf=requestAnimationFrame(loop);
}
function end(e,cancel){
  if(!d||(e&&e.pointerId!==d.pid))return;
  const x=d;d=null;cancelAnimationFrame(raf);
  x.card.classList.remove('dragging');x.card.style.transform='';clearMarks();
  document.body.classList.remove('is-dragging');
  try{x.handle.releasePointerCapture(x.pid)}catch(_){}
  if(!cancel&&x.target)place(x.id,x.target.dataset.id,x.after);
}
list.addEventListener('pointerdown',e=>{
  const h=e.target.closest('.drag-handle');
  if(!h||document.body.classList.contains('manager-mode')||(e.pointerType==='mouse'&&e.button!==0))return;
  const card=h.closest('.task');if(!card)return;
  e.preventDefault();
  d={card,handle:h,id:card.dataset.id,pid:e.pointerId,startY:e.clientY,y:e.clientY,startScroll:window.scrollY,target:null,after:false};
  try{h.setPointerCapture(e.pointerId)}catch(_){}
  card.classList.add('dragging');document.body.classList.add('is-dragging');
  raf=requestAnimationFrame(loop);
});
list.addEventListener('pointermove',e=>{if(d&&e.pointerId===d.pid){d.y=e.clientY;update()}});
list.addEventListener('pointerup',e=>end(e,false));
list.addEventListener('pointercancel',e=>end(e,true));
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&d)end({pointerId:d.pid},true)});
// Keyboard: focus the handle, then press ↑ / ↓
list.addEventListener('keydown',e=>{
  const h=e.target.closest&&e.target.closest('.drag-handle');
  if(!h||(e.key!=='ArrowUp'&&e.key!=='ArrowDown')||document.body.classList.contains('manager-mode'))return;
  e.preventDefault();
  const card=h.closest('.task'),id=card.dataset.id,nb=e.key==='ArrowUp'?card.previousElementSibling:card.nextElementSibling;
  if(!nb||!nb.dataset.id)return;
  if(place(id,nb.dataset.id,e.key==='ArrowDown')){const n=list.querySelector('.task[data-id="'+id+'"] .drag-handle');if(n)n.focus()}
});
})();

// Project Tasks is a separate view from the dashboard.
(function(){
  function syncTasksPage(){
    document.body.classList.toggle('tasks-page', location.hash === '#tasks');
  }
  function openTasksPage(status){
    const statusFilter=document.getElementById('statusFilter');
    const brandFilter=document.getElementById('brandFilter');
    const search=document.getElementById('search');
    const priorityFilter=document.getElementById('priorityFilter');
    const typeFilter=document.getElementById('typeFilter');
    if(statusFilter) statusFilter.value = status || '';
    // KPI shortcuts should show the full matching status group, not a leftover brand/search filter.
    if(brandFilter) brandFilter.value = '';
    if(search) search.value = '';
    if(priorityFilter) priorityFilter.value = '';
    if(typeFilter) typeFilter.value = '';
    if(typeof render === 'function') render();
    if(location.hash !== '#tasks') location.hash = 'tasks';
    else syncTasksPage();
    window.scrollTo(0,0);
  }
  function openDashboard(){ history.pushState(null,'',location.pathname+location.search); syncTasksPage(); window.scrollTo(0,0); }
  const cardFilters = {
    totalTaskCard: '',
    completedTaskCard: '100',
    inProgressTaskCard: 'inprogress'
  };
  window.addEventListener('hashchange', syncTasksPage);
  window.addEventListener('popstate', syncTasksPage);
  document.addEventListener('click', function(e){
    const card=e.target.closest('#totalTaskCard, #completedTaskCard, #inProgressTaskCard');
    if(card) openTasksPage(cardFilters[card.id]);
    if(e.target.closest('#backToDashboard')) openDashboard();
  });
  document.addEventListener('keydown', function(e){
    const card=e.target.closest('#totalTaskCard, #completedTaskCard, #inProgressTaskCard');
    if(card && (e.key==='Enter'||e.key===' ')){ e.preventDefault(); openTasksPage(cardFilters[card.id]); }
  });
  syncTasksPage();
})();
;

/* ===== Script 4 ===== */
// Designer board: hold & drag a card to another stage column (mouse, touch, pen)
(function(){
const list=document.getElementById('taskList');
const STAGES=[0,25,50,75,100];
let d=null,raf=0;
function colAt(x,y){
  const els=document.elementsFromPoint(x,y);
  for(const el of els){const c=el.closest&&el.closest('.dz-col');if(c&&list.contains(c))return c}
  return null;
}
function clearOver(){list.querySelectorAll('.dz-col.dz-over').forEach(c=>c.classList.remove('dz-over'))}
function loop(){
  if(!d||!d.active)return;
  const board=list.querySelector('.dz-board'),edge=80;let vx=0,vy=0;
  if(board){const r=board.getBoundingClientRect();
    if(d.x<r.left+edge)vx=-Math.ceil((r.left+edge-d.x)/5);else if(d.x>r.right-edge)vx=Math.ceil((d.x-(r.right-edge))/5);
    if(vx)board.scrollLeft+=vx}
  if(d.y<edge)vy=-Math.ceil((edge-d.y)/5);else if(d.y>innerHeight-edge)vy=Math.ceil((d.y-(innerHeight-edge))/5);
  if(vy)scrollBy(0,vy);
  if(vx||vy)hover();
  raf=requestAnimationFrame(loop);
}
function hover(){
  clearOver();
  const c=colAt(d.x,d.y);d.col=c;
  if(c)c.classList.add('dz-over');
}
function start(){
  d.active=true;
  const r=d.card.getBoundingClientRect();
  d.offX=d.startX-r.left;d.offY=d.startY-r.top;
  const f=d.card.cloneNode(true);
  f.classList.add('dz-float');f.style.width=r.width+'px';
  document.body.appendChild(f);d.float=f;
  d.card.classList.add('dz-ghost');
  document.body.classList.add('dz-dragging');
  raf=requestAnimationFrame(loop);
}
function move(){
  d.float.style.left=(d.x-d.offX)+'px';d.float.style.top=(d.y-d.offY)+'px';
  hover();
}
function finish(e,cancel){
  if(!d||(e&&e.pointerId!==d.pid))return;
  const x=d;d=null;cancelAnimationFrame(raf);
  if(!x.active)return;
  x.float.remove();x.card.classList.remove('dz-ghost');
  document.body.classList.remove('dz-dragging');clearOver();
  // swallow the click that follows a drag
  const swallow=ev=>{ev.stopPropagation();ev.preventDefault()};
  window.addEventListener('click',swallow,true);
  setTimeout(()=>window.removeEventListener('click',swallow,true),80);
  if(cancel||!x.col)return;
  const idx=[...list.querySelectorAll('.dz-col')].indexOf(x.col);
  if(idx<0||idx>=STAGES.length)return;
  const t=tasks.find(t=>t.id===x.id);
  if(!t||t.progress===STAGES[idx])return;
  t.dzNew=false;t.editedAt=new Date().toISOString();
  setProgress(x.id,STAGES[idx]);
}
list.addEventListener('pointerdown',e=>{
  const card=e.target.closest('.dz-card');
  if(!card||!list.contains(card))return;
  if(e.target.closest('button,a,input,select,textarea'))return;
  if(e.pointerType==='mouse'&&e.button!==0)return;
  if(document.body.classList.contains('manager-mode'))return;
  d={card,id:card.dataset.id,pid:e.pointerId,startX:e.clientX,startY:e.clientY,x:e.clientX,y:e.clientY,active:false,col:null};
  if(e.pointerType==='mouse')e.preventDefault();
});
document.addEventListener('pointermove',e=>{
  if(!d||e.pointerId!==d.pid)return;
  d.x=e.clientX;d.y=e.clientY;
  if(!d.active){
    if(Math.hypot(d.x-d.startX,d.y-d.startY)<6)return;
    start();
  }
  e.preventDefault();move();
},{passive:false});
document.addEventListener('pointerup',e=>finish(e,false));
document.addEventListener('pointercancel',e=>finish(e,true));
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&d&&d.active)finish({pointerId:d.pid},true)});
// stop native image/text drag from hijacking the gesture
list.addEventListener('dragstart',e=>{if(e.target.closest&&e.target.closest('.dz-card'))e.preventDefault()});
})();
;

/* ===== Script 5 ===== */
// Archived page (designer): #archived
(function(){
  const B=document.body;
  function sync(){B.classList.toggle('archive-page',location.hash==='#archived'&&B.classList.contains('designer-ui'))}
  window.dzArchSync=sync;
  function go(h){if(h){if(location.hash!=='#'+h)location.hash=h;else sync()}else{history.pushState(null,'',location.pathname+location.search);sync()}window.scrollTo(0,0)}
  document.addEventListener('click',e=>{
    if(e.target.closest('#archivedBtn')){if(typeof render==='function')render();go('archived')}
    else if(e.target.closest('#archBackDash'))go('');
    else if(e.target.closest('#archToBoard')){B.classList.remove('archive-page');go('tasks')}
  });
  document.getElementById('archSearch').addEventListener('input',()=>dzArchiveRender());
  window.addEventListener('hashchange',sync);window.addEventListener('popstate',sync);
  sync();
})();
;

/* ===== Script 6 ===== */
// Designer board: click a card to open its details in a slide-out panel
(function(){
const STAGE_NAMES={0:'Brief received',25:'Designing',50:'In review',75:'Revision',100:'Delivered'};
const STAGE_KEYS=[0,25,50,75,100];
const back=document.createElement('div');back.className='dzd-back';
const panel=document.createElement('aside');panel.className='dzd';panel.setAttribute('role','dialog');panel.setAttribute('aria-modal','true');panel.setAttribute('aria-label','Task details');panel.tabIndex=-1;
document.body.appendChild(back);document.body.appendChild(panel);
let openId=null,lastFocus=null;
const q=s=>panel.querySelector(s);
function todayStr(){const d=new Date();return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')}
function fmtDT(v){if(!v)return '';const d=new Date(v);return isNaN(d)?'':d.toLocaleString(undefined,{day:'numeric',month:'short',year:'numeric',hour:'numeric',minute:'2-digit'})}
function deadlineNote(t){
  if(!t.deadline)return '';
  const diff=Math.round((new Date(t.deadline+'T00:00:00')-new Date(todayStr()+'T00:00:00'))/864e5);
  if(Number(t.progress)>=100||t.archived==='done')return '<div class="sub2 ok">Completed</div>';
  if(diff<0)return `<div class="sub2 late">Overdue by ${-diff} day${diff===-1?'':'s'}</div>`;
  if(diff===0)return '<div class="sub2 late">Due today</div>';
  if(diff===1)return '<div class="sub2 soon">Due tomorrow</div>';
  return `<div class="sub2 ${diff<=5?'soon':'ok'}">${diff} days left</div>`;
}
function statusLabel(t){
  if(t.archived==='done')return '✓ Done (archived)';
  if(t.archived==='removed')return '🗑 Removed (archived)';
  const today=todayStr();
  if(t.deadline&&t.deadline<today&&Number(t.progress)<100)return '⚠ Missed deadline (archived)';
  return '';
}
function cell(label,val,extra,full){return `<div class="dzd-cell${full?' full':''}"><small>${label}</small><b>${val}</b>${extra||''}</div>`}
function fileHtml(r){
  const isImg=r.file&&String(r.type||'').startsWith('image/');
  const href=esc(r.url);
  const thumb=isImg?`<img src="${href}" alt="" loading="lazy">`:`<span class="dzd-ico">${r.file?'📎':'🔗'}</span>`;
  const sub=r.file?('File'+(r.size?' · '+sizeFmt(r.size):'')):esc(r.url);
  return `<a class="dzd-file" href="${href}" target="_blank" rel="noopener">${thumb}<div><b>${esc(r.name||(r.file?'File':'Reference'))}</b><span>${sub}</span></div></a>`;
}
function linkify(s){return esc(s).replace(/(https?:\/\/[^\s<]+)/g,'<a href="$1" target="_blank" rel="noopener" style="color:var(--blue)">$1</a>')}
function briefHtml(t){const b=t.brief;if(!b)return '';const rows=[['Event name',b.eventName],['Key message',b.keyMessage],['Mood &amp; tone',b.mood],['Creative',b.creative],['Size',b.size],['Reference',b.reference]];
  return `<section class="dzd-sec"><h4>Brief from ${esc(t.requestedBy||'brand')}</h4><div class="dzd-brief">${rows.map(([l,v])=>`<div class="dzd-bf"><small>${l}</small><div>${v&&String(v).trim()?linkify(String(v).trim()):'<span class="dzd-none">—</span>'}</div></div>`).join('')}</div></section>`}
function remarksHtml(t){
  const list=t.remarks||[],canAdd=!!(ACTIVE&&ACTIVE.dzRemark);
  if(t.brand!=='Designer')return '';
  if(!list.length&&!canAdd)return '';
  const items=list.map(r=>`<div class="dzd-remark"><div class="dzd-remark-top"><b>💬 ${esc(r.by||'Lead')}</b><span>${esc(fmtDT(r.at))}</span></div><p>${esc(r.text)}</p>${canAdd&&r.user===ACTIVE.user?`<button type="button" class="text-btn dz-del" data-dzr-del="${esc(r.id)}">Delete</button>`:''}</div>`).join('');
  const form=canAdd?`<div class="dzd-remark-form"><textarea id="dzRemarkInput" placeholder="Write a remark for ${esc(t.designer||'the designer')} — it will be saved under your name (${esc(ACTIVE.dzName)})"></textarea><button type="button" class="btn-primary" data-dzr="add">Send remark as ${esc(ACTIVE.dzName)}</button></div>`:'';
  return `<section class="dzd-sec"><h4>Remarks from lead (${list.length})</h4>${items||'<div class="dzd-none">No remarks yet.</div>'}${form}</section>`}
function build(t){
  const _kept=(q&&panel.querySelector('#dzRemarkInput'))?panel.querySelector('#dzRemarkInput').value:'';
  const prog=Math.max(0,Math.min(100,Number(t.progress)||0));
  const stageIdx=Math.max(0,STAGE_KEYS.indexOf(prog));
  const isDz=t.brand==='Designer',mgr=document.body.classList.contains('manager-mode');
  const st=statusLabel(t);
  const probs=t.problems||[];
  const nOpen=probs.filter(p=>!p.resolved).length;
  const notes=(t.notes||'').trim();
  const refs=t.refs||[];
  const rb=t.requestedBy||((String(t.owner||'').match(/^Requested by\s+(.+)$/i)||[])[1])||((String(t.name||'').match(/^\[([^\]]+)\]/)||[])[1])||'';const from=rb?cell('Requested by',esc(rb)):'';
  panel.innerHTML=`
  <div class="dzd-head">
    <button type="button" class="dzd-close" data-dzd-close aria-label="Close details">✕</button>
    <div class="dzd-kicker">${isDz?'Design request':'Project task'}</div>
    <h3 class="dzd-title">${esc(t.name)}</h3>
    <div class="dzd-pills">
      <span class="pill ${esc(String(t.priority||'Normal').toLowerCase())}">${esc(t.priority||'Normal')}</span>
      ${typePill(t)}
      ${t.dzNew?'<span class="pill urgent">NEW</span>':''}
      ${nOpen?`<span class="pill urgent">${nOpen} open problem${nOpen>1?'s':''}</span>`:''}
      ${st?`<span class="pill">${st}</span>`:''}
    </div>
  </div>
  <div class="dzd-body">
    <section class="dzd-sec"><h4>Stage</h4>
      <div class="dzd-stage">
        <div class="dzd-stage-top"><span>${isDz?(STAGE_NAMES[prog]||prog+'%'):(prog>=100?'Completed':prog>0?'In progress':'Not started')}</span><span>${prog}%</span></div>
        <div class="progress"><div class="fill" style="width:${prog}%"></div></div>
        <div class="dzd-steps">${STAGE_KEYS.map((k,i)=>`<span class="${i<=stageIdx?'on':''}"></span>`).join('')}</div>
        <div class="dzd-labels">${isDz?'<span>Brief</span><span>Design</span><span>Review</span><span>Revision</span><span>Delivered</span>':'<span>0%</span><span>25%</span><span>50%</span><span>75%</span><span>100%</span>'}</div>
      </div>
    </section>
    <section class="dzd-sec"><h4>Details</h4>
      <div class="dzd-grid">
        ${isDz?from:cell('Brand',esc(t.brand||'—'))}
        ${cell('Assigned to',esc(t.owner||'Unassigned'))}
        ${cell('Project type',esc(t.type||'—'))}
        ${cell('Start date',t.startDate?dateFmt(t.startDate):'—')}
        ${cell('Deadline',t.deadline?dateFmt(t.deadline):'No deadline',deadlineNote(t))}
        ${(isDz||t.designer)?cell('Designer responsible',esc(t.designer||'Not assigned')):''}
        ${t.taskId?cell('Task ID',esc(t.taskId)):''}
        ${t.editedAt?cell('Last edited',esc(fmtDT(t.editedAt)),'',true):''}
        ${t.archivedAt?cell('Archived',esc(fmtDT(t.archivedAt)),'',true):''}
      </div>
    </section>
    ${briefHtml(t)}${(notes||!t.brief)?`<section class="dzd-sec"><h4>Description / notes</h4>${notes?`<div class="dzd-notes">${esc(notes)}</div>`:'<div class="dzd-none">No notes added.</div>'}</section>`:''}
    ${remarksHtml(t)}
    <section class="dzd-sec"><h4>Files &amp; references (${refs.length})</h4>${refs.length?`<div class="dzd-files">${refs.map(fileHtml).join('')}</div>`:'<div class="dzd-none">No files or links attached.</div>'}</section>
    <section class="dzd-sec"><h4>Problems (${probs.length})</h4>${probs.length?probs.map(p=>`<div class="dzd-issue ${p.resolved?'res':''}"><b>${esc(p.title)} <span class="pill ${p.severity==='High'?'urgent':p.severity==='Medium'?'important':''}">${esc(p.severity||'')}</span>${p.resolved?' <span class="pill">Resolved</span>':''}</b><p>${esc(p.reporter||'Team member')}${p.details?' · '+esc(p.details):''}</p></div>`).join(''):'<div class="dzd-none">No problems reported.</div>'}</section>
  </div>
  <div class="dzd-foot">
    ${mgr?'':'<button type="button" class="btn-light" data-dzd="edit">✎ Edit</button>'}
    <button type="button" class="btn-light" data-dzd="files">📎 Files</button>
    ${!isDz?'':t.archived?`<button type="button" class="btn-light" data-dzd="restore">↩ Restore</button>`:`<button type="button" class="btn-primary" data-dzd="done">✓ Done</button>`}
  </div>`;
  if(_kept){const ta=panel.querySelector('#dzRemarkInput');if(ta)ta.value=_kept}
}
panel.addEventListener('click',e=>{
  const add=e.target.closest('[data-dzr="add"]'),del=e.target.closest('[data-dzr-del]');
  if(!add&&!del)return;
  if(!ACTIVE||!ACTIVE.dzRemark)return;
  const t=tasks.find(x=>x.id===openId);if(!t)return;
  if(add){
    const ta=panel.querySelector('#dzRemarkInput'),txt=ta?ta.value.trim():'';
    if(!txt){if(ta)ta.focus();return}
    t.remarks=t.remarks||[];
    t.remarks.push({id:id(),by:ACTIVE.dzName,user:ACTIVE.user,text:txt,at:new Date().toISOString()});
    if(ta)ta.value='';
  }else{
    const rid=del.getAttribute('data-dzr-del');
    t.remarks=(t.remarks||[]).filter(r=>!(r.id===rid&&r.user===ACTIVE.user));
  }
  save();build(t);
});
window.dzOpenDetail=function(id){open(id)};
function find(id){return tasks.find(t=>t.id===id)}
function open(id){
  const t=find(id);if(!t)return;
  if(t.dzNew){t.dzNew=false;save()}
  lastFocus=document.activeElement;openId=id;
  build(t);
  back.classList.add('show');panel.classList.add('show');document.body.classList.add('dzd-open');
  panel.querySelector('.dzd-body').scrollTop=0;
  setTimeout(()=>{const c=q('.dzd-close');if(c)c.focus()},50);
  if(window.render)render();
}
function close(){
  if(!openId)return;openId=null;
  back.classList.remove('show');panel.classList.remove('show');document.body.classList.remove('dzd-open');
  if(lastFocus&&lastFocus.focus&&document.contains(lastFocus)){try{lastFocus.focus()}catch(e){}}
}
function refresh(){
  if(!openId)return;
  const t=find(openId);
  if(!t){close();return}
  const sc=q('.dzd-body')?q('.dzd-body').scrollTop:0;
  build(t);const b=q('.dzd-body');if(b)b.scrollTop=sc;
}
// Open from board cards and archived cards (ignore buttons/links and the click after a drag)
document.addEventListener('click',e=>{
  if(!document.body.classList.contains('designer-ui'))return;
  const card=e.target.closest('.dz-card,.dz-acard');
  if(!card||e.target.closest('button,a,input,select,textarea'))return;
  if(card.classList.contains('dz-ghost'))return;
  open(card.dataset.id);
});
back.addEventListener('click',close);
panel.addEventListener('click',e=>{
  if(e.target.closest('[data-dzd-close]')){close();return}
  const b=e.target.closest('[data-dzd]');if(!b||!openId)return;
  const id=openId,act=b.dataset.dzd;
  if(act==='edit'){close();editTask(id)}
  else if(act==='files'){close();showRefs(id)}
  else if(act==='done'){close();dzDone(id)}
  else if(act==='restore'){close();dzRestore(id)}
});
document.addEventListener('keydown',e=>{
  if(!openId)return;
  if(e.key==='Escape'){close();return}
  if(e.key==='Tab'){
    const f=[...panel.querySelectorAll('button,a[href]')].filter(x=>!x.disabled);
    if(!f.length)return;
    const first=f[0],last=f[f.length-1];
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus()}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus()}
  }
});
// Keep the panel in sync when tasks change (live updates, drag, edits)
const _r=render;
render=function(){_r();refresh()};
// Close if the user leaves the designer view
window.addEventListener('hashchange',()=>{if(openId&&!document.body.classList.contains('tasks-page')&&!document.body.classList.contains('archive-page'))close()});
})();
;

/* ===== Script 7 ===== */
(function(){const _o=openTask;openTask=function(t){_o(t);const row=document.getElementById('dzDesignerRow'),inp=document.getElementById('taskDesigner');row.style.display=(lockBrand()==='Designer'||t?.brand==='Designer')?'':'none';inp.value=t?.designer||'';const names=[...new Set(ACCOUNTS.map(a=>a.dzName).concat(tasks.map(x=>x.designer)).filter(Boolean))];document.getElementById('dzDesignerList').innerHTML=names.map(n=>'<option value="'+esc(n)+'">').join('')}})();
;

/* ===== Script 8 ===== */
// Request designer -> brief pop-up
(function(){
const $=id=>document.getElementById(id);
const cb=$('taskDzReq'),row=$('dzReqRow'),form=$('dzBriefForm');
window.dzPendingBrief=null;
const sum=document.createElement('div');sum.id='dzBriefSummary';sum.className='notice';sum.style.cssText='display:none;margin:8px 0 0';row.appendChild(sum);
function updSum(){const b=window.dzPendingBrief;if(!b){sum.style.display='none';sum.innerHTML='';return}
  sum.style.display='';sum.innerHTML='✓ Brief ready for the designer: <b>'+esc(b.eventName)+'</b> · <button type="button" class="text-btn" id="dzBriefEdit">Edit brief</button><br><span class="small">Now click <b>Save task</b> to save everything and alert the designer.</span>'}
function openBrief(){const b=window.dzPendingBrief||{};
  $('dzbEvent').value=b.eventName||'';$('dzbKey').value=b.keyMessage||'';$('dzbMood').value=b.mood||'';$('dzbCreative').value=b.creative||'';$('dzbSize').value=b.size||'';$('dzbRef').value=b.reference||'';
  show('dzBriefModal');setTimeout(()=>$('dzbEvent').focus(),50)}
function cancelBrief(){hide('dzBriefModal');if(!window.dzPendingBrief)cb.checked=false}
cb.addEventListener('change',()=>{if(cb.checked)openBrief();else{window.dzPendingBrief=null;updSum()}});
sum.addEventListener('click',e=>{if(e.target.id==='dzBriefEdit')openBrief()});
form.addEventListener('submit',e=>{e.preventDefault();
  for(const i of ['dzbEvent','dzbKey','dzbMood','dzbCreative','dzbSize']){const el=$(i);if(!el.value.trim()){el.value='';el.reportValidity();return}}
  window.dzPendingBrief={eventName:$('dzbEvent').value.trim(),keyMessage:$('dzbKey').value.trim(),mood:$('dzbMood').value.trim(),creative:$('dzbCreative').value.trim(),size:$('dzbSize').value.trim(),reference:$('dzbRef').value.trim()};
  hide('dzBriefModal');updSum()});
$('dzBriefCancel').onclick=cancelBrief;$('dzBriefClose').onclick=cancelBrief;
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&$('dzBriefModal').classList.contains('show'))cancelBrief()});
// Can't save the task with "Request designer" ticked until the brief is filled in
document.addEventListener('submit',e=>{if(e.target.id!=='taskForm')return;
  if(cb.checked&&row.style.display!=='none'&&!window.dzPendingBrief){e.preventDefault();e.stopImmediatePropagation();openBrief()}},true);
const _o=openTask;
openTask=function(t){_o(t);window.dzPendingBrief=null;updSum();
  const lab=$('taskNotes').previousElementSibling;
  if(lab)lab.textContent=(lockBrand()==='Designer'||t?.brand==='Designer')?'Description / notes':'Description / notes (private — the designer can’t see this)'};
})();
;

/* ===== Script 9 ===== */
// ===== Designer bell: tasks due today + alerts at 10:00 AM and 4:00 PM =====
(function(){
const $=id=>document.getElementById(id);
const SLOTS=[[10,'10:00 AM'],[16,'4:00 PM']],FKEY='dzNotifFired';
const wrap=$('dzBellWrap'),btn=$('dzBell'),badge=$('dzBellBadge'),menu=$('dzBellMenu');
const box=document.createElement('div');box.id='dzToasts';document.body.appendChild(box);
const isDz=()=>lockBrand()==='Designer';
const loadF=()=>{try{return JSON.parse(localStorage.getItem(FKEY)||'{}')}catch(e){return {}}};
const saveF=o=>{try{localStorage.setItem(FKEY,JSON.stringify(o))}catch(e){}};
function dueToday(){const d=dzToday();return isDz()?scopedTasks().filter(t=>t.deadline===d&&Number(t.progress)<100&&!t.archived):[]}
const stageOf=t=>{const s=DZ_STAGES.find(x=>x[0]===Number(t.progress));return s?s[1]:''};
function update(){
  const list=dueToday();
  badge.textContent=list.length;badge.style.display=list.length?'flex':'none';
  const head='<div class="dz-bell-head">Due today <small>'+dateFmt(dzToday())+'</small></div>';
  const body=list.length?'<div class="dz-bell-list">'+list.map(t=>'<button type="button" class="dz-bell-item" data-id="'+t.id+'"><b>'+esc(t.name)+'</b><span>'+esc(t.priority)+' · '+esc(stageOf(t))+' · '+esc(t.owner||'Unassigned')+'</span></button>').join('')+'</div>':'<div class="dz-bell-empty">🎉 Nothing is due today.</div>';
  menu.innerHTML='<div class="dz-bell-card">'+head+body+'<div class="dz-bell-foot">Alerts at 10:00 AM and 4:00 PM for tasks due today.<br><button type="button" class="text-btn" id="dzSoundBtn">'+(soundOn()?'🔊 Sound on · turn off':'🔇 Sound off · turn on')+'</button></div></div>'}
let AC=null;
function ctx(){try{if(!AC){const A=window.AudioContext||window.webkitAudioContext;AC=new A()}if(AC.state==='suspended')AC.resume();return AC}catch(e){return null}}
['click','keydown','touchstart'].forEach(ev=>document.addEventListener(ev,()=>ctx(),{once:true,passive:true}));
const soundOn=()=>{try{return localStorage.getItem('dzSound')!=='off'}catch(e){return true}};
function beep(force){
  if(!force&&!soundOn())return;
  const c=ctx();if(!c)return;
  // three-note chime, played twice
  const notes=[[784,0],[988,.18],[1175,.36],[784,.9],[988,1.08],[1175,1.26]];
  notes.forEach(([f,d])=>{const o=c.createOscillator(),g=c.createGain(),t=c.currentTime+d;o.type='sine';o.frequency.value=f;o.connect(g);g.connect(c.destination);g.gain.setValueAtTime(0.0001,t);g.gain.exponentialRampToValueAtTime(.35,t+.02);g.gain.exponentialRampToValueAtTime(.0001,t+.45);o.start(t);o.stop(t+.5)})}
function notify(label,tasks){
  const t=document.createElement('div');t.className='dz-toast';
  t.innerHTML='<h5>⏰ '+label+' reminder · '+tasks.length+' task'+(tasks.length>1?'s':'')+' due today</h5><ul>'+tasks.map(x=>'<li>'+esc(x.name)+'</li>').join('')+'</ul><div class="row"><button class="btn-light" data-a="view">View board</button><button class="btn-light" data-a="x">Dismiss</button></div>';
  t.onclick=e=>{const a=e.target.dataset.a;if(a==='view')location.hash='tasks';if(a)t.remove()};
  box.appendChild(t);
  btn.classList.remove('ring');void btn.offsetWidth;btn.classList.add('ring');
  beep();
  try{if(window.Notification&&Notification.permission==='granted')new Notification('Due today · '+label,{body:tasks.map(x=>x.name).join('\n')})}catch(e){}}
function tick(){
  if(!isDz())return;
  const now=new Date(),today=dzToday(),F=loadF();
  Object.keys(F).forEach(k=>{if(k.indexOf(today+'|')!==0)delete F[k]});
  const passed=SLOTS.filter(x=>now.getHours()>=x[0]);
  if(passed.length){
    const latest=passed[passed.length-1],fresh=[];
    dueToday().forEach(t=>passed.forEach(x=>{const k=today+'|'+x[0]+'|'+t.id;if(!F[k]){F[k]=1;if(x[0]===latest[0])fresh.push(t)}}));
    if(fresh.length)notify(latest[1],fresh)}
  saveF(F);update()}
btn.addEventListener('click',()=>{wrap.classList.toggle('open');try{if(window.Notification&&Notification.permission==='default')Notification.requestPermission()}catch(e){}});
document.addEventListener('click',e=>{if(!wrap.contains(e.target))wrap.classList.remove('open')});
menu.addEventListener('click',e=>{if(e.target.id==='dzSoundBtn'){const on=soundOn();try{localStorage.setItem('dzSound',on?'off':'on')}catch(x){}update();if(!on)beep(true);return}if(e.target.closest('.dz-bell-item')){wrap.classList.remove('open');location.hash='tasks'}});
const _r=render;render=function(){_r();update();tick()};
setInterval(tick,20000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)tick()});
update();tick();
})();
;

/* ===== Script 10 ===== */
// Problem tracking: click High / Medium / Low to list the tasks that have problems of that severity
window.sevFilter='';
function chartSeverity(v){
  ['priorityFilter','brandFilter','typeFilter','statusFilter','search'].forEach(i=>{const e=document.getElementById(i);if(e)e.value=''});
  window.sevFilter=v;render();
  if(location.hash!=='#tasks')location.hash='tasks';else window.dispatchEvent(new Event('hashchange'));
  window.scrollTo(0,0);
}
(function(){
  const clear=()=>{if(window.sevFilter){window.sevFilter='';render()}};
  ['chartStatus','chartBrand','chartPriority','chartOwner'].forEach(n=>{const f=window[n];if(typeof f==='function')window[n]=function(){window.sevFilter='';return f.apply(this,arguments)}});
  document.addEventListener('click',e=>{
    if(e.target.closest('#sevClear'))clear();
    else if(e.target.closest('#clearChartFilters,#totalTaskCard,#completedTaskCard,#inProgressTaskCard,#backToDashboard'))window.sevFilter='';
  },true);
  const _r=render;
  render=function(){_r();
    const b=document.getElementById('sevBanner');if(!b)return;
    const on=!!window.sevFilter;b.hidden=!on;b.style.display=on?'flex':'none';
    if(on){const n=document.querySelectorAll('#taskList .task,#taskList .dz-card').length;
      document.getElementById('sevBannerText').innerHTML='Showing tasks with <b>'+window.sevFilter+'</b> severity problems · '+n+' task'+(n===1?'':'s')}
  };
  render();
})();
;

/* ===== Script 11 ===== */
// ===== Team helpers: overdue flags, quick filters, duplicate task, copy report, shortcuts =====
(function(){
const $=id=>document.getElementById(id);
const pad=n=>String(n).padStart(2,'0');
const ymd=d=>d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate());
const today=()=>ymd(new Date());
const inDays=n=>{const d=new Date();d.setDate(d.getDate()+n);return ymd(d)};
const isOpen=t=>Number(t.progress)<100&&!t.archived;
const isOverdue=t=>t.deadline&&t.deadline<today()&&isOpen(t);
const hasProblem=t=>(t.problems||[]).some(p=>!p.resolved);
function visibleTasks(){
  if(typeof lockBrand==='function'&&lockBrand())return scopedTasks();
  if(typeof mgrBrand!=='undefined'&&mgrBrand)return tasks.filter(t=>t.brand===mgrBrand);
  return tasks;
}
const FILTERS=[
  ['','All',()=>true],
  ['overdue','⚠ Overdue',isOverdue],
  ['today','Due today',t=>isOpen(t)&&t.deadline===today()],
  ['week','Next 7 days',t=>isOpen(t)&&t.deadline&&t.deadline>=today()&&t.deadline<=inDays(7)],
  ['problem','Has problem',t=>isOpen(t)&&hasProblem(t)],
  ['unassigned','Unassigned',t=>isOpen(t)&&!String(t.owner||'').trim()]
];
let qf='';
// Quick filter bar above the task list
const list=$('taskList');
const bar=document.createElement('div');
bar.id='quickBar';bar.className='dz-chips';bar.style.margin='0 0 12px';
list.parentNode.insertBefore(bar,list);
const empty=document.createElement('div');
empty.className='empty';empty.id='qfEmpty';empty.style.display='none';empty.textContent='No tasks match this quick filter.';
list.parentNode.insertBefore(empty,list.nextSibling);
bar.addEventListener('click',e=>{const b=e.target.closest('[data-qf]');if(!b)return;qf=b.dataset.qf;render()});

// Duplicate a task (copy with 0% progress, no problems, links only)
window.dupTask=function(tid){
  const src=tasks.find(t=>t.id===tid);if(!src)return;
  const c=JSON.parse(JSON.stringify(src));
  c.id=id();c.name=src.name+' (copy)';c.progress=0;c.problems=[];c.taskId='';
  c.refs=(c.refs||[]).filter(r=>!r.file);
  ['order','archived','archivedAt','editedAt','fromTask','designerRequested','dzNew','remarks'].forEach(k=>delete c[k]);
  tasks.unshift(c);save();render();
  if(typeof syncStatus==='function')syncStatus('Task duplicated ✓');
};

// Copy a plain-text status report for chat / email
function report(){
  const v=visibleTasks(),d=new Date();
  const line=t=>'• '+t.name+(t.owner?' — '+t.owner:'')+(t.deadline?' (due '+t.deadline+', '+(Number(t.progress)||0)+'%)':'');
  const over=v.filter(isOverdue),week=v.filter(t=>isOpen(t)&&t.deadline&&t.deadline>=today()&&t.deadline<=inDays(7)),prob=v.filter(t=>isOpen(t)&&hasProblem(t));
  const done=v.filter(t=>Number(t.progress)===100).length,doing=v.filter(t=>Number(t.progress)>0&&Number(t.progress)<100).length;
  const scope=(typeof lockBrand==='function'&&lockBrand())||(typeof mgrBrand!=='undefined'&&mgrBrand)||'All brands';
  const sec=(h,a)=>a.length?'\n'+h+' ('+a.length+')\n'+a.map(line).join('\n')+'\n':'';
  return 'Team Project Status — '+scope+' — '+d.toDateString()+'\nTotal '+v.length+' · Completed '+done+' · In progress '+doing+'\n'+
    sec('⚠ OVERDUE',over)+sec('DUE IN NEXT 7 DAYS',week)+sec('OPEN PROBLEMS',prob);
}
const rb=document.createElement('button');
rb.className='btn-light';rb.id='reportBtn';rb.type='button';rb.textContent='📋 Copy report';rb.title='Copy a status summary to paste into chat or email';
const ex=$('exportBtn');ex.parentNode.insertBefore(rb,ex.nextSibling);
rb.onclick=async()=>{
  const txt=report();
  try{await navigator.clipboard.writeText(txt)}catch(e){const ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);ta.select();try{document.execCommand('copy')}catch(x){}ta.remove()}
  if(typeof syncStatus==='function')syncStatus('Report copied — paste it anywhere ✓');
};

// Decorate rendered cards + dashboard
function enhance(){
  const v=visibleTasks(),dz=document.body.classList.contains('designer-ui');
  // overdue count on dashboard alert card
  const tb=document.querySelector('.stat.alertcard .task-breakdown');
  if(tb){let row=$('overdueRow');if(!row){row=document.createElement('div');row.id='overdueRow';row.innerHTML='<span>Overdue:</span><b id="overdueCount">0</b>';tb.appendChild(row)}$('overdueCount').textContent=v.filter(isOverdue).length}
  // quick filter bar
  bar.style.display=dz?'none':'';
  if(!dz){
    bar.innerHTML=FILTERS.map(([k,l,fn])=>'<button type="button" class="dz-chip'+(qf===k?' on':'')+'" data-qf="'+k+'">'+l+' <span>'+v.filter(fn).length+'</span></button>').join('');
    const fn=(FILTERS.find(f=>f[0]===qf)||FILTERS[0])[2];
    let shown=0;const cards=list.querySelectorAll('.task[data-id]');
    cards.forEach(c=>{const t=tasks.find(x=>x.id===c.dataset.id);const ok=!t||fn(t);c.style.display=ok?'':'none';if(ok)shown++;
      if(t){
        const pills=c.querySelector('.pills');
        if(pills&&isOverdue(t)&&!pills.querySelector('.ovd')){const s=document.createElement('span');s.className='pill urgent ovd';s.textContent='Overdue';pills.insertBefore(s,pills.firstChild)}
        const links=c.querySelectorAll('.task-links'),last=links[links.length-1];
        if(last&&!last.querySelector('.dup')){const b=document.createElement('button');b.className='text-btn dup';b.textContent='Duplicate';b.onclick=()=>dupTask(t.id);last.insertBefore(b,last.firstChild)}
      }});
    empty.style.display=(cards.length&&!shown)?'':'none';
  }else empty.style.display='none';
}
const _r=render;render=function(){_r();enhance()};

// Shortcuts: "/" search · "N" new task
document.addEventListener('keydown',e=>{
  if(e.ctrlKey||e.metaKey||e.altKey)return;
  const el=document.activeElement,typing=el&&/^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName);
  if(typing||!ACTIVE||document.querySelector('.modal-back.show'))return;
  if(e.key==='/'){e.preventDefault();if(location.hash!=='#tasks')location.hash='tasks';setTimeout(()=>{const s=$('search');if(s)s.focus()},60)}
  else if((e.key==='n'||e.key==='N')&&!document.body.classList.contains('manager-mode')){e.preventDefault();openTask()}
});
render();
})();
;
