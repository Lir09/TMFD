/* ===== 상태 ===== */
const monthLabel = document.getElementById('monthLabel');
const calBody = document.getElementById('calBody');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');
const calendarEl = document.getElementById('calendar');
const btnMonth = document.getElementById('btnMonth');
const btnWeek = document.getElementById('btnWeek');

const today = new Date(); today.setHours(0,0,0,0);
let viewDate = new Date(today.getFullYear(), today.getMonth(), 1);
let mode = 'month'; // 'month' | 'week'

/* ===== 이벤트 예시 ===== */
const EVENTS = {
  "2025-08-13": ["개학"],
  "2025-08-15": ["광복절"],
  "2025-09-03": ["전국연합학력평가"],
  "2025-09-11": ["1차 입학설명회"],
  "2025-09-29": ["중간고사"],
  "2025-09-30": ["중간고사"],
  "2025-10-01": ["중간고사"],
  "2025-10-02": ["중간고사"],
  "2025-10-03": ["개천절"],
};

const pad = n => String(n).padStart(2,'0');
const toISO = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;

function startOfMonthGrid(y, m) {
  const first = new Date(y, m, 1);
  return new Date(y, m, 1 - first.getDay()); // 해당 월 첫 주 일요일
}
function startOfWeek(d) {
  const dd = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  return new Date(dd.setDate(dd.getDate() - dd.getDay())); // 일요일
}

/* ===== 렌더링 ===== */
function setLabel() {
  if (mode === 'month') {
    monthLabel.textContent = `${viewDate.getFullYear()}년 ${viewDate.getMonth()+1}월`;
  } else {
    const start = startOfWeek(viewDate);
    const end = new Date(start); end.setDate(end.getDate()+6);
    const fmt = d => `${d.getFullYear()}년 ${d.getMonth()+1}월 ${d.getDate()}일`;
    monthLabel.textContent = `${fmt(start)} ~ ${fmt(end)}`;
  }
}

const logo = document.getElementById('reloaded'); // id 그대로 써도 됨(함수 삭제 전제)
logo.addEventListener('click', (e) => {
  e.preventDefault();          // '#'로 맨 위 점프 방지
  window.location.reload();    // 페이지 리로드
});

function render() {
  setLabel();
  calBody.innerHTML = '';
  calendarEl.classList.toggle('is-week', mode === 'week');

  if (mode === 'month') {
    const y = viewDate.getFullYear();
    const m = viewDate.getMonth();
    let cursor = startOfMonthGrid(y, m);

    for (let i=0;i<42;i++) {
      const d = new Date(cursor);
      const inMonth = (d.getMonth() === m);
      calBody.appendChild(makeCell(d, !inMonth));
      cursor.setDate(cursor.getDate()+1);
    }
  } else {
    // 주간: viewDate가 포함된 주의 7일만
    const start = startOfWeek(viewDate);
    for (let i=0;i<7;i++) {
      const d = new Date(start); d.setDate(start.getDate()+i);
      calBody.appendChild(makeCell(d, false));
    }
  }
}

function makeCell(dateObj, muted) {
  const cell = document.createElement('div');
  cell.className = 'day' + (muted ? ' muted' : '');

  if (dateObj.getTime() === today.getTime()) cell.classList.add('today');

  const dateSpan = document.createElement('span');
  dateSpan.className = 'date';
  dateSpan.textContent = dateObj.getDate();
  cell.appendChild(dateSpan);

  const key = toISO(dateObj);
  if (EVENTS[key] && EVENTS[key].length) {
    cell.classList.add('has-dot');
    const ev = document.createElement('div');
    ev.className = 'event';
    ev.textContent = EVENTS[key][0];
    cell.appendChild(ev);
  }
  return cell;
}
/* 에니메이션 효과*/
const text = "Time Management For Daeshin"; // 처음에 타이핑될 문구
const shortText = "TMFD"; // 클릭 후 변환될 문구
const el = document.getElementById("typingTitle");
let i = 0;
let typingDone = false;

// /* 1) 타자기 효과 */
// function typing(){
//   if(i < text.length){
//     el.textContent += text.charAt(i);
//     i++;
//     setTimeout(typing, 80);
//   } else {
//     typingDone = true; // 다 치고 나면 상태 저장
//   }
// }
// typing();

// /* 2) 클릭 시 변환 */
// el.addEventListener("click", () => {
//   if (!typingDone) return; // 다 타이핑되기 전엔 클릭 막기

//   el.classList.add("fade-out");
//   setTimeout(() => {
//     el.textContent = shortText; // TMFD로 교체
//     el.classList.remove("fade-out");
//     el.classList.add("fade-in");
//   }, 500); // fade-out 끝난 후 교체
// });

/* ===== 네비게이션 ===== */
prevBtn.addEventListener('click', () => {
  if (mode === 'month') {
    viewDate = new Date(viewDate.getFullYear(), viewDate.getMonth()-1, 1);
  } else {
    viewDate = new Date(viewDate.getFullYear(), viewDate.getMonth(), viewDate.getDate()-7);
  }
  render();
});
nextBtn.addEventListener('click', () => {
  if (mode === 'month') {
    viewDate = new Date(viewDate.getFullYear(), viewDate.getMonth()+1, 1);
  } else {
    viewDate = new Date(viewDate.getFullYear(), viewDate.getMonth(), viewDate.getDate()+7);
  }
  render();
});

/* ===== 보기 전환 ===== */
function activate(view) {
  mode = view;
  btnMonth.classList.toggle('active', view==='month');
  btnWeek.classList.toggle('active', view==='week');
  render();
}
btnMonth.addEventListener('click', () => activate('month'));
btnWeek.addEventListener('click', () => activate('week'));

/* 최초 렌더 */
render();
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("showCodeBtn");

  if (btn) {
    btn.addEventListener("click", () => {
      fetch("/api/kakao/pair/start", { method: "POST" })
        .then(r => r.json())
        .then(data => {
          if (data.code) {
            alert(`인증코드: ${data.code}`);
          } else {
            alert("코드 발급 실패");
          }
        })
        .catch(err => {
          console.error(err);
          alert("서버 오류");
        });
    });
  }
});

