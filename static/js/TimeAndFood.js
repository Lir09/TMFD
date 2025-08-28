/* ===== 1) 과목 기본 담당(문자열/배열 가능) ===== */
const TEACHERS = {
  "종교":"강준원", "유도":"김윤철", "진로":"이진희",
  "공영2":"성우열", "통과2":"신용운",
  "공국2":"사선혜", "공수2":"이종문", "통사2":"김영실",
  "정보":"강철규", "음악":"김성종", "한국2":"장태준",
  "체육":"송원근", "과탐실2":"이진용",
  "공강":null, "비어있음":null
};

/* ===== 2) 요일별 과목 담당(요일→과목→교사[문자/배열]) ===== */
const DAY_SUBJECT_TEACHERS = {
  "월": { "통과2":"신용운" },
  "화": { "통과2":"이희택" },
};

/* ===== 3) 교시별 오버라이드(선택) ===== */
const OVERRIDES = {
  "화":{"5" : ["고윤성"]}
  // "수": { "2": ["보조A","보조B"] },
};

/* ===== 4) 시간표(월~금, 1~7교시) ===== */
const DAYS = ["일","월","화","수","목","금","토"];
const PERIODS = [1,2,3,4,5,6,7];

const TIMETABLE = {
  "월": ["종교","유도","진로","공영2","통과2","공국2","공수2"],
  "화": ["공수2","통사2","음악","한국2","통사2","통과2","공영2"],
  "수": ["공국2","정보","통사2","통과2","공강","한국2","공영2"],
  "목": ["공국2","공영2","한국2","체육","공수2","음악","정보"],
  "금": ["과탐실2","정보","공수2","음악","비어있음","비어있음","비어있음"]
};

/* ===== 5) 종/휴 & 점심시간 ===== */
const BELL = [
  {p:1, start:"08:30", end:"09:20"},
  {p:2, start:"09:30", end:"10:20"},
  {p:3, start:"10:30", end:"11:20"},
  {p:4, start:"11:30", end:"12:20"},
  {p:5, start:"13:40", end:"14:30"},
  {p:6, start:"14:40", end:"15:30"},
  {p:7, start:"15:40", end:"16:30"},
];
const LUNCH = { start:"12:20", end:"13:40" };

/* ===== 6) 유틸 ===== */
function kstNow(){ return new Date(); }
function formatDateKorean(d){
  const y=d.getFullYear(), m=String(d.getMonth()+1).padStart(2,"0"), da=String(d.getDate()).padStart(2,"0");
  return `${y}-${m}-${da} (${DAYS[d.getDay()]})`;
}
function isFree(subject){ return !subject || subject==="공강" || subject==="비어있음"; }
function parseHM(hm){ const [h,m]=hm.split(":").map(Number); return h*60+m; }
function minutesNow(d){ return d.getHours()*60 + d.getMinutes(); }

/* ===== 7) 현재 상태 계산 ===== */
function getNowState(dayIdx){
  const now = kstNow(); const nowMin = minutesNow(now);
  if (nowMin >= parseHM(LUNCH.start) && nowMin < parseHM(LUNCH.end)){
    return {state:"lunch", pIndex:-1, label:"점심시간"};
  }
  for (let i=0;i<BELL.length;i++){
    const s=parseHM(BELL[i].start), e=parseHM(BELL[i].end);
    if(nowMin>=s && nowMin<e) return {state:"class", pIndex:i, label:`${BELL[i].p}교시 수업 중`};
  }
  return {state:"break", pIndex:-1, label:"쉬는 시간"};
}

/* ===== 8) 교사명 해석(오버라이드 → 요일별 → 기본) ===== */
function getTeachers(subject, dayKey, periodNum){
  const ov = OVERRIDES?.[dayKey]?.[String(periodNum)];
  if (ov && ov.length) return Array.isArray(ov) ? ov.join(" · ") : ov;

  const dayMap = DAY_SUBJECT_TEACHERS?.[dayKey]?.[subject];
  if (dayMap) return Array.isArray(dayMap) ? dayMap.join(" · ") : dayMap;

  const base = TEACHERS[subject];
  if (!base) return "";
  return Array.isArray(base) ? base.join(" · ") : base;
}

/* ===== 9) 테이블 렌더링 ===== */
function renderTable(todayColIdx, nowRowIdx){
  const table = document.getElementById("timetable");
  table.innerHTML = "";

  // 헤더
  const trHead = document.createElement("tr");
  const th0 = document.createElement("th"); th0.className="period"; th0.textContent="교시";
  trHead.appendChild(th0);
  const weekdays=["월","화","수","목","금"];
  weekdays.forEach((d,i)=>{
    const th=document.createElement("th"); th.textContent=d;
    if(i+1===todayColIdx) th.classList.add("today-col");
    trHead.appendChild(th);
  });
  table.appendChild(trHead);

  // 본문
  PERIODS.forEach((p, rowIdx)=>{
    const tr=document.createElement("tr");
    if (nowRowIdx===rowIdx) tr.classList.add("now-row");

    const tdPeriod=document.createElement("td");
    tdPeriod.className="period";
    tdPeriod.textContent=`${p}교시`;
    tr.appendChild(tdPeriod);

    ["월","화","수","목","금"].forEach((dayLabel, i)=>{
      const subj = TIMETABLE[dayLabel]?.[p-1] || "";
      const teacherTxt = getTeachers(subj, dayLabel, p);

      const td=document.createElement("td");
      td.className="subject-cell";
      if(i+1===todayColIdx) td.classList.add("today-col");

      if(isFree(subj)){
        td.innerHTML=`<span class="free">${subj || "-"}</span>`;
      }else{
        td.innerHTML=`
          <span class="subject-pill">${subj}</span>
          <small>${teacherTxt}</small>
        `;
      }
      tr.appendChild(td);
    });

    table.appendChild(tr);
  });
}

/* ===== 10) 오늘 리스트 렌더링 ===== */
function renderTodayList(dayIdx, nowRowIdx){
  const list = document.getElementById("todayList");
  const badge = document.getElementById("dayBadge");
  list.innerHTML = "";

  if(dayIdx===0 || dayIdx===6){
    badge.textContent="주말";
    const msg=document.createElement("div");
    msg.className="row";
    msg.innerHTML = `<div class="left"><span class="chip">-</span><div>
      <div class="txt">수업 없음</div>
      <div class="teacher">두뇌 캐시 비우는 날</div>
    </div></div>`;
    list.appendChild(msg);
    return;
  }

  const weekdays = ["일","월","화","수","목","금","토"];
  badge.textContent=`${weekdays[dayIdx]}요일`;

  const dayKey = ["월","화","수","목","금"][dayIdx-1];
  const arr = TIMETABLE[dayKey] || [];

  PERIODS.forEach((p, idx)=>{
    const subj = arr[p-1] || "";
    const teachers = getTeachers(subj, dayKey, p);

    const row=document.createElement("div");
    row.className="row";
    if (nowRowIdx===idx) row.classList.add("now");

    row.innerHTML = `
      <div class="left">
        <span class="chip">${p}교시</span>
        <div>
          <div class="txt">${subj || "-"}</div>
          <div class="teacher">${isFree(subj) ? "공강/자습" : teachers}</div>
        </div>
      </div>
      <div class="right">${isFree(subj) ? "휴식" : "수업"}</div>
    `;
    list.appendChild(row);
  });
}

/* ===== 11) 상태 배지 렌더링 ===== */
function renderStatus(dayIdx, nowState){
  const stateEl = document.getElementById("stateBadge");
  const nextEl  = document.getElementById("nextBadge");

  if(dayIdx===0 || dayIdx===6){
    stateEl.textContent = "주말";
    nextEl.textContent = "";
    return;
  }
  const dayKey = ["월","화","수","목","금"][dayIdx-1];

  if(nowState.state==="lunch"){
    stateEl.textContent = `지금: 점심시간 (${LUNCH.start}~${LUNCH.end})`;
    nextEl.textContent  = nextClassInfo(dayKey);
    return;
  }
  if(nowState.state==="break"){
    stateEl.textContent = "지금: 쉬는 시간";
    nextEl.textContent  = nextClassInfo(dayKey);
    return;
  }
  if(nowState.state==="class"){
    const bell = BELL[nowState.pIndex];
    const periodNum = bell.p;
    const subj = TIMETABLE[dayKey]?.[periodNum-1] || "";
    const teachers = getTeachers(subj, dayKey, periodNum);
    stateEl.textContent = `지금: ${periodNum}교시 ${subj} (${bell.start}~${bell.end})`;
    if(!isFree(subj) && teachers) stateEl.textContent += ` · ${teachers}`;
    nextEl.textContent = nextClassInfo(dayKey, nowState.pIndex+1);
  }
}

function nextClassInfo(dayKey, fromIndex=0){
  for(let i=fromIndex;i<BELL.length;i++){
    const subj = TIMETABLE[dayKey]?.[BELL[i].p-1] || "";
    if(!isFree(subj)){
      const t = getTeachers(subj, dayKey, BELL[i].p);
      return `다음: ${BELL[i].p}교시 ${subj} ${t?`· ${t}`:""} (${BELL[i].start}~${BELL[i].end})`;
    }
  }
  return "다음: 오늘 수업 종료";
}

/* ===== 12) 초기화 & 1분 자동 갱신 ===== */
(function init(){
  const now = kstNow();
  document.getElementById("todayInfo").textContent = formatDateKorean(now);

  const dayIdx = now.getDay(); // 0=일 ... 6=토
  const todayColIdx = (dayIdx>=1 && dayIdx<=5) ? dayIdx : -1;

  const state = getNowState(dayIdx);
  const nowRowIdx = (dayIdx>=1 && dayIdx<=5 && state.state==="class") ? state.pIndex : -1;

  renderTable(todayColIdx, nowRowIdx);
  renderTodayList(dayIdx, nowRowIdx);
  renderStatus(dayIdx, state);

  setInterval(()=>{
    const d = kstNow();
    const dayIdx2 = d.getDay();
    const state2 = getNowState(dayIdx2);
    const nowRowIdx2 = (dayIdx2>=1 && dayIdx2<=5 && state2.state==="class") ? state2.pIndex : -1;
    renderTable((dayIdx2>=1 && dayIdx2<=5)?dayIdx2:-1, nowRowIdx2);
    renderTodayList(dayIdx2, nowRowIdx2);
    renderStatus(dayIdx2, state2);
    document.getElementById("todayInfo").textContent = formatDateKorean(d);
  }, 60*1000);
})();