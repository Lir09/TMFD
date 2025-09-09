/* ============================ State ============================ */
const state = {
  role: "student",
  subject: "ALL",
  query: "",
  status: "",
  sort: "due",
  items: [],
};

/* ============================ Helpers (동일) ============================ */
const $ = (q, root = document) => root.querySelector(q);
const $$ = (q, root = document) => Array.from(root.querySelectorAll(q));
// ... fmtDateTime, msRemaining, fmtRemain, pillFor, toast 그대로 둬도 됨 ...

/* ============================ 서버 통신 ============================ */
async function fetchUser() {
  const res = await fetch("/api/user");
  const data = await res.json();
  state.role = data.role || "student";
}

async function fetchAssessments() {
  const res = await fetch("/api/assessments");
  if (!res.ok) {
    $("#needClass").classList.remove("hidden");
    return;
  }
  const data = await res.json();
  state.items = data.map((it) => ({
    id: it.id,
    subj: it.subject,
    title: it.title,
    type: it.type,
    due: it.due_at,
    status: it.status,
    progress: it.progress,
    checklist: it.checklist || [],
    checks: (it.checklist || []).map(() => 0), // 서버 반영할거면 status 저장 필요
  }));
}

/* ============================ Render (동일) ============================ */
// renderHeader, filteredItems, renderRows, renderBuckets, openDetail 등 그대로 두되
// openDetail에서 상태 변경/체크리스트 수정 → 서버 PATCH 호출 추가

async function updateStatus(id, newStatus) {
  await fetch(`/api/assessments`, {
    method: "POST", // 서버에서 PATCH 구현시 PATCH로 바꾸기
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, status: newStatus }),
  });
}

function openDetail(id) {
  const it = state.items.find((x) => x.id === id);
  if (!it) return;
  $("#dwTitle").textContent = it.title;
  $("#dwSubj").textContent = it.subj;
  $("#dwType").textContent = it.type;
  $("#dwDue").textContent = `${fmtDateTime(it.due)} (${fmtRemain(it.due)})`;
  $("#dwStatus").textContent = it.status;
  $("#dwProg").style.width = `${it.progress}%`;

  const ul = $("#dwList");
  ul.innerHTML = "";
  it.checklist.forEach((txt, idx) => {
    const li = document.createElement("li");
    const idc = `dwchk-${id}-${idx}`;
    li.innerHTML = `
      <input id="${idc}" type="checkbox" ${it.checks[idx] ? "checked" : ""}/>
      <label for="${idc}" style="flex:1">${txt}</label>
    `;
    li.querySelector("input").addEventListener("change", async (e) => {
      it.checks[idx] = e.target.checked ? 1 : 0;
      const total = it.checklist.length;
      const done = it.checks.filter((v) => v).length;
      it.progress = Math.round((done / total) * 100);
      renderRows();
      renderBuckets();

      // 서버 반영 (PATCH 필요)
      await fetch(`/api/assessments`, {
        method: "POST", // 나중에 PATCH 엔드포인트 추가 시 수정
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: it.id, progress: it.progress }),
      });
    });
    ul.appendChild(li);
  });

  const act = $("#dwActions");
  act.innerHTML = "";
  if (state.role === "admin" || state.role === "leader") {
    const btn = document.createElement("button");
    btn.className = "btn";
    btn.textContent = "상태: 다음 단계";
    btn.addEventListener("click", async () => {
      const order = ["미제출", "진행중", "제출", "채점중", "완료"];
      const i = Math.max(0, order.indexOf(it.status));
      it.status = order[Math.min(order.length - 1, i + 1)];
      toast(`상태가 '${it.status}'(으)로 변경되었습니다`);
      renderRows();
      renderBuckets();
      // 서버 반영
      await updateStatus(it.id, it.status);
      openDetail(id);
    });
    act.appendChild(btn);
  }
  $("#drawer").classList.add("show");
}

/* ============================ Add Drawer ============================ */
async function createFromAdd() {
  const subj = $("#adSubject").value.trim();
  const title = $("#adTitle").value.trim();
  const type = $("#adType").value.trim();
  const due = $("#adDue").value;
  const status = $("#adStatus").value.trim();
  const prog = Math.max(
    0,
    Math.min(100, parseInt($("#adProg").value || "0", 10))
  );
  const list = $("#adList")
    .value.split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  if (!title || !due) {
    toast("제목/마감은 필수");
    return;
  }

  const res = await fetch("/api/assessments", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      subject: subj,
      title,
      type,
      due_at: due,
      status,
      progress: prog,
      checklist: list,
    }),
  });
  if (res.ok) {
    await fetchAssessments();
    closeAdd();
    renderRows();
    renderBuckets();
    toast("새 과제가 등록되었습니다");
  } else {
    toast("등록 실패");
  }
}

/* ============================ Init ============================ */
async function init() {
  await fetchUser();
  await fetchAssessments();
  renderHeader();
  renderRows();
  renderBuckets();
  setupEvents();
}
document.addEventListener("DOMContentLoaded", init);
