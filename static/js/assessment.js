/* ============================ State (sample) ============================ */
// NOTE: 실제 로그인 로직에서 role을 주입하세요: "student" | "leader" | "admin"
const state = {
  role: "leader", // 예시값. 운영 연동 시 실제 권한으로 교체
  subject: "ALL",
  query: "",
  status: "",
  sort: "due",
  items: [
    {
      id: "a1", subj: "국어",   title:"광장 독서감상문", type:"보고서",
      due:"2025-09-10T23:59", status:"진행중", progress:45,
      checklist:["책 읽기","구성 정리","초안 작성","최종 제출"], checks:[1,1,0,0]
    },
    {
      id: "a2", subj: "영어",   title:"Poetic Devices 발표", type:"발표",
      due:"2025-09-09T20:00", status:"미제출", progress:10,
      checklist:["작품 선정","예문 수집","슬라이드"], checks:[1,0,0]
    },
    {
      id: "a3", subj: "한국사", title:"편전·조총 비교 보고", type:"실험",
      due:"2025-09-08T18:00", status:"채점중", progress:100,
      checklist:["자료조사","실험 설계","실험 수행","정리"], checks:[1,1,1,1]
    },
    {
      id: "a4", subj: "정보",   title:"TMFD UI 리팩터", type:"코딩",
      due:"2025-09-12T18:00", status:"진행중", progress:30,
      checklist:["디자인 합치기","행 클릭 상세","추가 드로어"], checks:[1,1,0]
    }
  ]
};

/* ============================ Helpers ============================ */
const $ = (q,root=document)=>root.querySelector(q);
const $$ = (q,root=document)=>Array.from(root.querySelectorAll(q));

const fmtDateTime = (iso)=>{
  if(!iso) return "-";
  const d = new Date(iso);
  const y = d.getFullYear();
  const m = (d.getMonth()+1).toString().padStart(2,"0");
  const dd = d.getDate().toString().padStart(2,"0");
  const hh = d.getHours().toString().padStart(2,"0");
  const mm = d.getMinutes().toString().padStart(2,"0");
  return `${y}-${m}-${dd} ${hh}:${mm}`;
};

const msRemaining = (iso)=> new Date(iso).getTime() - Date.now();

const fmtRemain = (iso)=>{
  const ms = msRemaining(iso);
  const sign = ms < 0 ? -1 : 1;
  const abs = Math.abs(ms);
  const d = Math.floor(abs/86400000);
  const h = Math.floor((abs%86400000)/3600000);
  const m = Math.floor((abs%3600000)/60000);
  const txt = d ? `${d}일 ${h}시간` : (h ? `${h}시간 ${m}분` : `${m}분`);
  return sign<0 ? `지각 ${txt}` : `${txt} 남음`;
};

const pillFor = (iso)=>{
  const ms = msRemaining(iso);
  if(ms < 0) return ['pill red','지각'];
  if(ms <= 48*3600000) return ['pill yellow','임박'];
  return ['pill green','정상'];
};

const toast = (msg)=>{
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 1600);
};

/* ============================ Render ============================ */
function renderHeader(){
  const now = new Date();
  const y = now.getFullYear(), m=String(now.getMonth()+1).padStart(2,'0'), d=String(now.getDate()).padStart(2,'0');
  $('#today').textContent = `${y}-${m}-${d}`;

  // 관리자만 배지 + 추가버튼 표시
  if(state.role === 'admin'){
    $('#roleBadge').classList.remove('hidden');
    $('#roleBadge').textContent = 'ADMIN';
    $('#addBtn').classList.remove('hidden');
  }else{
    $('#roleBadge').classList.add('hidden');
    $('#addBtn').classList.add('hidden');
  }
}

function filteredItems(){
  return state.items
    .filter(it => state.subject==='ALL' ? true : it.subj===state.subject)
    .filter(it => state.status ? it.status===state.status : true)
    .filter(it => state.query ? (it.title+it.subj+it.type).toLowerCase().includes(state.query.toLowerCase()) : true)
    .sort((a,b)=>{
      if(state.sort==='due'){
        return new Date(a.due)-new Date(b.due);
      }else if(state.sort==='remaining'){
        return msRemaining(a.due)-msRemaining(b.due);
      }else{
        return b.progress - a.progress; // progress desc
      }
    });
}

function renderRows(){
  const wrap = $('#rows'); wrap.innerHTML = '';
  const list = filteredItems();
  $('#empty').classList.toggle('hidden', list.length!==0);
  $('#needClass').classList.add('hidden'); // hook

  list.forEach(it=>{
    const row = document.createElement('div');
    row.className='row';
    row.dataset.id = it.id;

    const [pillCls, pillTxt] = pillFor(it.due);

    row.innerHTML = `
      <div class="chk"><input type="checkbox" data-id="${it.id}" /></div>
      <div>${it.subj}</div>
      <div>
        <div style="font-weight:600">${it.title}</div>
        <div class="muted" style="font-size:12px">${it.type} · 진행률 ${it.progress}%</div>
      </div>
      <div><span class="pill ${pillCls.split(' ')[1]}">${it.type}</span></div>
      <div>${fmtDateTime(it.due)}</div>
      <div><span class="${pillCls}">${fmtRemain(it.due)}</span></div>
    `;
    row.addEventListener('click',(e)=>{
      if(e.target.tagName==='INPUT') return; // ignore checkbox
      openDetail(it.id);
    });
    wrap.appendChild(row);
  });
}

function renderBuckets(){
  const todayWrap = $('#todayList');
  const soonWrap  = $('#soonList');
  const lateWrap  = $('#lateList');
  todayWrap.innerHTML = soonWrap.innerHTML = lateWrap.innerHTML = '';

  const start = new Date(); start.setHours(0,0,0,0);
  const end   = new Date(); end.setHours(23,59,59,999);

  const pushItem = (wrap, it)=>{
    const el = document.createElement('div');
    el.className='item';
    el.innerHTML = `
      <div class="ttl">${it.title}</div>
      <div class="muted">${it.subj} · ${fmtDateTime(it.due)} · ${fmtRemain(it.due)}</div>
    `;
    el.addEventListener('click',()=>openDetail(it.id));
    wrap.appendChild(el);
  };

  state.items.forEach(it=>{
    const due = new Date(it.due);
    if(due<new Date()) { pushItem(lateWrap, it); return; }
    const within48 = msRemaining(it.due) <= 48*3600000;
    if(due>=start && due<=end) pushItem(todayWrap, it);
    else if(within48) pushItem(soonWrap, it);
  });

  if(!todayWrap.children.length) todayWrap.innerHTML = `<div class="item">등록된 항목이 없습니다.</div>`;
  if(!soonWrap.children.length)  soonWrap.innerHTML  = `<div class="item">없음</div>`;
  if(!lateWrap.children.length)  lateWrap.innerHTML  = `<div class="item">없음</div>`;
}

/* ============================ Detail Drawer ============================ */
function openDetail(id){
  const it = state.items.find(x=>x.id===id); if(!it) return;
  $('#dwTitle').textContent = it.title;
  $('#dwSubj').textContent  = it.subj;
  $('#dwType').textContent  = it.type;
  $('#dwDue').textContent   = `${fmtDateTime(it.due)} (${fmtRemain(it.due)})`;
  $('#dwStatus').textContent= it.status;
  $('#dwProg').style.width  = `${it.progress}%`;

  const ul = $('#dwList'); ul.innerHTML = '';
  it.checklist.forEach((txt, idx)=>{
    const li = document.createElement('li');
    const idc = `dwchk-${id}-${idx}`;
    li.innerHTML = `
      <input id="${idc}" type="checkbox" ${it.checks[idx] ? 'checked':''}/>
      <label for="${idc}" style="flex:1">${txt}</label>
    `;
    li.querySelector('input').addEventListener('change',(e)=>{
      it.checks[idx] = e.target.checked ? 1 : 0;
      const total = it.checklist.length;
      const done  = it.checks.filter(v=>v).length;
      it.progress = Math.round(done/total*100);
      renderRows(); renderBuckets();
    });
    ul.appendChild(li);
  });

  // 관리자/리더 동작 버튼 (상태 다음 단계) — 표시 자체는 모두 가능
  const act = $('#dwActions'); act.innerHTML='';
  const btn = document.createElement('button');
  btn.className='btn';
  btn.textContent='상태: 다음 단계';
  btn.addEventListener('click',()=>{
    const order = ["미제출","진행중","제출","채점중","완료"];
    const i = Math.max(0, order.indexOf(it.status));
    it.status = order[Math.min(order.length-1, i+1)];
    toast(`상태가 '${it.status}'(으)로 변경되었습니다`);
    openDetail(id); renderRows(); renderBuckets();
  });
  act.appendChild(btn);

  $('#drawer').classList.add('show');
}
function closeDetail(){ $('#drawer').classList.remove('show'); }

/* ============================ Add Drawer ============================ */
function openAdd(){ $('#addDrawer').classList.add('show'); }
function closeAdd(){ $('#addDrawer').classList.remove('show'); }

function createFromAdd(){
  const subj = $('#adSubject').value.trim();
  const title= $('#adTitle').value.trim();
  const type = $('#adType').value.trim();
  const due  = $('#adDue').value;
  const status=$('#adStatus').value.trim();
  const prog = Math.max(0, Math.min(100, parseInt($('#adProg').value||'0',10)));
  const list = $('#adList').value.split('\n').map(s=>s.trim()).filter(Boolean);

  if(!title || !due){ toast('제목/마감은 필수'); return; }

  state.items.push({
    id:'n'+(Date.now().toString(36)),
    subj, title, type, due, status, progress:prog,
    checklist:list, checks:list.map(()=>0)
  });
  closeAdd();
  renderRows(); renderBuckets();
  toast('새 과제가 등록되었습니다');
}

/* ============================ Events ============================ */
function setupEvents(){
  // Tabs
  $$('#tabs .tab').forEach(btn=>{
    btn.addEventListener('click', (e)=>{
      $$('#tabs .tab').forEach(b=>b.classList.remove('is-active'));
      btn.classList.add('is-active');
      state.subject = btn.dataset.subj || 'ALL';

      // ripple
      const wrap = btn.querySelector('.ripple') || btn.appendChild(Object.assign(document.createElement('div'),{className:'ripple'}));
      const span = document.createElement('span');
      const rect = btn.getBoundingClientRect();
      span.style.left = (e.clientX - rect.left) + 'px';
      span.style.top  = (e.clientY - rect.top)  + 'px';
      wrap.appendChild(span);
      span.addEventListener('animationend', ()=> span.remove(), {once:true});

      renderRows(); renderBuckets();
    });
  });

  // Filters
  $('#q').addEventListener('input', (e)=>{ state.query=e.target.value; renderRows(); });
  $('#status').addEventListener('change', (e)=>{ state.status=e.target.value; renderRows(); });
  $('#sort').addEventListener('change', (e)=>{ state.sort=e.target.value; renderRows(); });
  $('#clear').addEventListener('click', ()=>{
    state.query=''; state.status=''; state.sort='due';
    $('#q').value=''; $('#status').value=''; $('#sort').value='due';
    renderRows();
  });

  // Drawers
  $('#dwClose').addEventListener('click', closeDetail);
  $('#drawer').addEventListener('click', (e)=>{ if(e.target.id==='drawer') closeDetail(); });

  // Add drawer (버튼 자체는 admin만 보이도록 renderHeader에서 제어)
  $('#addBtn').addEventListener('click', openAdd);
  $('#addCancel').addEventListener('click', closeAdd);
  $('#addCreate').addEventListener('click', createFromAdd);
  $('#addDrawer').addEventListener('click', (e)=>{ if(e.target.id==='addDrawer') closeAdd(); });
}

/* ============================ Init ============================ */
function init(){
  renderHeader();
  renderRows();
  renderBuckets();
  setupEvents();
}
document.addEventListener('DOMContentLoaded', init);
