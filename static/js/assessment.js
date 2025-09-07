/* ===================== State & Utils ===================== */
const State = {
  current: "ALL",
  q: "",
  st: "",
  sort: "due",
  isLeader: false,
  isAdmin: false,
  classId: null,
  data: [],
};

function fmtDateLocal(dt) {
  // dt: Date
  return dt.toLocaleString("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}
function parseISO(s) {
  // "YYYY-MM-DDTHH:MM" → Date(로컬로 해석)
  // Safari 호환: replace space
  return new Date(s.replace(" ", "T"));
}
function hoursLeft(dt) {
  return (dt - new Date()) / 36e5;
}
function dueClass(dt) {
  const h = hoursLeft(dt);
  if (h < 0) return "red";
  if (h <= 48) return "orange";
  return "gray";
}
function bySort(a, b, key) {
  if (key === "due") return a._due - b._due;
  if (key === "remaining") return hoursLeft(a._due) - hoursLeft(b._due);
  if (key === "progress") return (b.progress || 0) - (a.progress || 0);
  return 0;
}
function toast(msg, ms = 1800) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), ms);
}

/* ===================== DOM Refs & Header ===================== */
const rowsEl = document.getElementById("rows");
const tabsEl = document.getElementById("tabs");
const todayEl = document.getElementById("today");
const qEl = document.getElementById("q");
const stEl = document.getElementById("status");
const sortEl = document.getElementById("sort");
const addBtn = document.getElementById("addBtn");
const needClass = document.getElementById("needClass");
const emptyEl = document.getElementById("empty");
const roleBadge = document.getElementById("roleBadge");

document.getElementById("clear").onclick = () => {
  qEl.value = "";
  stEl.value = "";
  sortEl.value = "due";
  State.q = "";
  State.st = "";
  State.sort = "due";
  render();
};

todayEl.textContent = new Date().toLocaleString("ko-KR", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  weekday: "short",
  hour: "2-digit",
  minute: "2-digit",
});

/* ===================== Filters & Tabs ===================== */
tabsEl.addEventListener("click", (e) => {
  const b = e.target.closest(".tab");
  if (!b) return;
  document
    .querySelectorAll(".tab")
    .forEach((t) => t.classList.remove("active"));
  b.classList.add("active");
  State.current = b.dataset.subj;
  render();
});
qEl.oninput = (e) => {
  State.q = e.target.value.trim();
  render();
};
stEl.onchange = (e) => {
  State.st = e.target.value;
  render();
};
sortEl.onchange = (e) => {
  State.sort = e.target.value;
  render();
};

/* ===================== Drawer Helpers ===================== */
const detailDrawer = document.getElementById("drawer");
function openDrawer(x) {
  if (!x) return;
  document.getElementById("dwTitle").textContent = x.title;
  document.getElementById("dwSubj").textContent = x.subject;
  document.getElementById("dwType").textContent = x.type || "-";
  document.getElementById("dwDue").textContent = fmtDateLocal(x._due);
  document.getElementById("dwStatus").textContent = x.status || "-";
  document.getElementById("dwProg").style.width = (x.progress || 0) + "%";
  const ul = document.getElementById("dwList");
  ul.innerHTML = "";
  (x.checklist || []).forEach((t) =>
    ul.insertAdjacentHTML(
      "beforeend",
      `<li><input type="checkbox" disabled><span>${t}</span></li>`
    )
  );
  // actions (leader/admin could delete in the future)
  const actions = document.getElementById("dwActions");
  actions.innerHTML = "";
  if (State.isLeader || State.isAdmin) {
    const delBtn = document.createElement("button");
    delBtn.className = "btn danger";
    delBtn.textContent = "삭제";
    delBtn.onclick = async (ev) => {
      ev.stopPropagation();
      if (!confirm("정말 삭제할까요?")) return;
      const res = await fetch(`/api/assessments/${x.id}`, {
        method: "DELETE",
      });
      if (res.ok) {
        toast("삭제됨");
        closeDrawer();
        await loadData();
        render();
        fillSide();
      } else {
        const j = await res.json().catch(() => ({}));
        toast(j.error || "삭제 실패");
      }
    };
    actions.appendChild(delBtn);
  }
  detailDrawer.classList.add("open");
}
function closeDrawer() {
  detailDrawer.classList.remove("open");
}
detailDrawer.addEventListener("click", (e) => {
  if (e.target.id === "drawer") closeDrawer();
});

/* ===================== Add Drawer (leader/admin only) ===================== */
const addDrawer = document.getElementById("addDrawer");
const adSubject = document.getElementById("adSubject");
const adTitle = document.getElementById("adTitle");
const adType = document.getElementById("adType");
const adDue = document.getElementById("adDue");
const adStatus = document.getElementById("adStatus");
const adProg = document.getElementById("adProg");
const adList = document.getElementById("adList");

function openAdd() {
  addDrawer.classList.add("open");
}
function closeAdd() {
  addDrawer.classList.remove("open");
}
document.getElementById("addCancel").onclick = closeAdd;
addDrawer.addEventListener("click", (e) => {
  if (e.target.id === "addDrawer") closeAdd();
});

document.getElementById("addCreate").onclick = async () => {
  const subject = adSubject.value.trim();
  const title = adTitle.value.trim();
  const type = adType.value.trim();
  const due_at = adDue.value.trim(); // "YYYY-MM-DDTHH:MM"
  const status = adStatus.value.trim();
  const progress = Math.max(
    0,
    Math.min(100, parseInt(adProg.value || "0", 10))
  );
  const checklist = adList.value
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  if (!subject || !title || !due_at) {
    toast("과목/제목/마감은 필수입니다.");
    return;
  }

  const res = await fetch("/api/assessments", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      subject,
      title,
      type,
      due_at,
      status,
      progress,
      checklist,
    }),
  });
  if (res.ok) {
    toast("등록 완료");
    closeAdd();
    adTitle.value = "";
    adDue.value = "";
    adProg.value = "0";
    adList.value = "";
    await loadData();
    render();
    fillSide();
  } else {
    const j = await res.json().catch(() => ({}));
    toast(j.error || "등록 실패");
  }
};

/* ===================== Data Load & Render ===================== */
async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function loadMe() {
  const me = await fetchJSON("/api/user"); // 확장된 응답 사용
  if (!me.login) {
    location.href = "/login";
    return;
  }
  State.isAdmin = me.email === "admin@admin.com";
  State.isLeader = me.role === "leader";
  State.classId = me.class_id ?? null;

  // badge
  roleBadge.textContent = State.isAdmin
    ? "관리자 계정"
    : State.isLeader
    ? "반장 권한"
    : "학생 계정";

  // leader/admin만 추가 버튼 노출
  if (State.isLeader || State.isAdmin) {
    addBtn.style.display = "";
    addBtn.onclick = () => {
      if (!State.classId && !State.isAdmin) {
        toast("반 배정이 필요합니다.");
        return;
      }
      openAdd();
    };
  }
}

async function loadData() {
  if (!State.classId && !State.isAdmin) {
    // 반 미배정 학생이면 빈 목록 + 안내
    State.data = [];
    needClass.style.display = "";
    emptyEl.style.display = "none";
    rowsEl.innerHTML = "";
    return;
  }
  needClass.style.display = "none";

  // 관리자면 자신의 class_id 또는 쿼리 파라미터를 추가로 붙일 수 있지만
  // 여기서는 자신의 class_id 기준으로 조회(필요하면 ?class_id= 사용)
  const list = await fetchJSON("/api/assessments");
  // 가공
  State.data = list.map((x) => {
    const d = { ...x };
    d._due = parseISO(x.due_at);
    return d;
  });
}

function render() {
  rowsEl.innerHTML = "";
  let list = State.data
    .filter((x) => State.current === "ALL" || x.subject === State.current)
    .filter(
      (x) =>
        !State.q ||
        (x.title + (x.type || "") + x.subject)
          .toLowerCase()
          .includes(State.q.toLowerCase())
    )
    .filter((x) => !State.st || x.status === State.st)
    .sort((a, b) => bySort(a, b, State.sort));

  emptyEl.style.display = list.length
    ? "none"
    : State.classId || State.isAdmin
    ? ""
    : "none";

  list.forEach((x) => {
    const dueCls = dueClass(x._due);
    const remain = hoursLeft(x._due);
    const remainTxt =
      remain < 0
        ? `지각 ${Math.abs(remain).toFixed(1)}h`
        : `${remain.toFixed(1)}h`;
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <div class="cell"><input type="checkbox" aria-label="select" onclick="event.stopPropagation()"/></div>
      <div class="cell"><span class="pill">${x.subject}</span></div>
      <div class="cell title" title="${x.title}">${x.title}</div>
      <div class="cell"><span class="chip">${x.type || "-"}</span></div>
      <div class="cell due ${dueCls}">${fmtDateLocal(x._due)}</div>
      <div class="cell remain"><span class="badge">${remainTxt}</span></div>
    `;
    row.onclick = () => openDrawer(x);
    rowsEl.appendChild(row);
  });
}

/* Right buckets */
function fillSide() {
  const tList = document.getElementById("todayList");
  const sList = document.getElementById("soonList");
  const lList = document.getElementById("lateList");
  [tList, sList, lList].forEach((n) => (n.innerHTML = ""));

  const todayStr = new Date().toDateString();
  State.data.forEach((x) => {
    const h = hoursLeft(x._due);
    const item = (cls) => `
      <div class="task ${cls}">
        <div class="left">
          <span class="badge">${x.subject}</span>
          <div>
            <div>${x.title}</div>
            <div class="when">${fmtDateLocal(x._due)} · ${x.type || "-"}</div>
          </div>
        </div>
        <button class="btn" onclick="openDrawerFromSide('${
          x.id
        }')">상세</button>
      </div>`;
    if (h < 0) lList.insertAdjacentHTML("beforeend", item("late"));
    else if (x._due.toDateString() === todayStr)
      tList.insertAdjacentHTML("beforeend", item(""));
    else if (h <= 48) sList.insertAdjacentHTML("beforeend", item("warn"));
  });
}
window.openDrawerFromSide = (id) => {
  const x = State.data.find((v) => String(v.id) === String(id));
  if (x) openDrawer(x);
};

/* ===================== Boot ===================== */
(async function boot() {
  try {
    await loadMe();
    await loadData();
    render();
    fillSide();
  } catch (e) {
    console.error(e);
    toast("데이터 로드 실패");
  }
  // 1분마다 남은 시간만 갱신되어 보이도록 재렌더
  setInterval(() => {
    render();
    fillSide();
  }, 60 * 1000);
})();
