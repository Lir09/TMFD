/* ============================ State ============================ */
const state = {
  role: "student",
  subject: "ALL",
  query: "",
  status: "",
  sort: "due",
  items: [],
  uploadedImageUrl: ""
};

/* ============================ Helpers ============================ */
const $ = (q, root = document) => root.querySelector(q);
const $$ = (q, root = document) => Array.from(root.querySelectorAll(q));

function fmtDateTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString("ko-KR", { dateStyle: "short", timeStyle: "short" });
}

function msRemaining(iso) {
  return new Date(iso).getTime() - Date.now();
}

function fmtRemain(iso) {
  const ms = msRemaining(iso);
  if (ms < 0) return "지남";
  const h = Math.floor(ms / 1000 / 60 / 60);
  const d = Math.floor(h / 24);
  if (d > 0) return `${d}일 ${h % 24}시간`;
  return `${h}시간`;
}

function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2500);
}

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
    checks: (it.checklist || []).map(() => 0),
    description: it.description || "",
    rubricImage: it.rubric_image || "",
    files: it.files || []
  }));
}

async function updateStatus(id, newStatus) {
  await fetch(`/api/assessments/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: newStatus }),
  });
}

/* ============================ Render ============================ */
function renderHeader() {
  const today = new Date();
  $("#today").textContent = today.toLocaleDateString("ko-KR", {
    weekday: "long",
    month: "long",
    day: "numeric",
  });

  const badge = $("#roleBadge");
  if (state.role === "admin" || state.role === "leader") {
    badge.textContent = state.role;
    badge.classList.remove("hidden");
  }
}

function filteredItems() {
  return state.items
    .filter((it) => state.subject === "ALL" || it.subj === state.subject)
    .filter(
      (it) =>
        !state.query ||
        it.title.includes(state.query) ||
        it.subj.includes(state.query)
    )
    .filter((it) => !state.status || it.status === state.status)
    .sort((a, b) => {
      if (state.sort === "due") return new Date(a.due) - new Date(b.due);
      if (state.sort === "remaining")
        return msRemaining(a.due) - msRemaining(b.due);
      if (state.sort === "progress") return b.progress - a.progress;
      return 0;
    });
}

function renderRows() {
  const rows = $("#rows");
  rows.innerHTML = "";
  const items = filteredItems();
  if (items.length === 0) {
    $("#empty").classList.remove("hidden");
  } else {
    $("#empty").classList.add("hidden");
  }
  items.forEach((it) => {
    const div = document.createElement("div");
    div.className = "row";
    div.dataset.id = it.id;
    div.innerHTML = `
      <div><input type="checkbox"></div>
      <div>${it.subj}</div>
      <div>${it.title}</div>
      <div>${it.type}</div>
      <div>${fmtDateTime(it.due)}</div>
      <div>${fmtRemain(it.due)}</div>
    `;
    div.addEventListener("click", (e) => {
      if (e.target.tagName === "INPUT") return;
      openDetail(it.id);
    });
    rows.appendChild(div);
  });
}

function renderBuckets() {
  const todayList = $("#todayList");
  const soonList = $("#soonList");
  const lateList = $("#lateList");
  todayList.innerHTML = soonList.innerHTML = lateList.innerHTML = "";

  const now = Date.now();
  state.items.forEach((it) => {
    const ms = msRemaining(it.due);
    const el = document.createElement("div");
    el.textContent = `${it.subj} - ${it.title} (${fmtRemain(it.due)})`;
    el.style.cursor = "pointer";
    el.addEventListener("click", () => openDetail(it.id));

    if (ms < 0) lateList.appendChild(el);
    else if (ms < 1000 * 60 * 60 * 48) soonList.appendChild(el);
    else if (new Date(it.due).getDate() === new Date().getDate())
      todayList.appendChild(el);
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

  // 설명 표시
  const descEl = $("#dwDescription");
  if (it.description) {
    descEl.textContent = it.description;
    descEl.style.display = "block";
  } else {
    descEl.style.display = "none";
  }

  // 평가기준표 이미지 표시
  const rubricEl = $("#dwRubricImage");
  if (it.rubricImage) {
    rubricEl.src = it.rubricImage;
    rubricEl.parentElement.style.display = "block";
  } else {
    rubricEl.parentElement.style.display = "none";
  }

  // 체크리스트
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

      await fetch(`/api/assessments/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ progress: it.progress }),
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
      await updateStatus(it.id, it.status);
      openDetail(id);
    });
    act.appendChild(btn);
  }
  $("#drawer").classList.add("show");
}

/* ============================ Add Drawer ============================ */
async function uploadRubricImage() {
  const fileInput = $("#adRubricImage");
  const file = fileInput.files[0];
  
  if (!file) {
    toast("이미지를 선택해주세요");
    return;
  }

  const formData = new FormData();
  formData.append("image", file);

  try {
    $("#uploadProgress").style.display = "block";
    const res = await fetch("/api/assessments/upload-image", {
      method: "POST",
      body: formData
    });

    const data = await res.json();
    
    if (res.ok) {
      state.uploadedImageUrl = data.url;
      $("#uploadedImagePreview").src = data.url;
      $("#imagePreviewContainer").style.display = "block";
      toast("이미지 업로드 완료!");
    } else {
      toast(data.error || "업로드 실패");
    }
  } catch (err) {
    toast("서버 오류: " + err.message);
  } finally {
    $("#uploadProgress").style.display = "none";
  }
}

async function createFromAdd() {
  const subj = $("#adSubject").value.trim();
  const title = $("#adTitle").value.trim();
  const type = $("#adType").value.trim();
  const due = $("#adDue").value;
  const status = $("#adStatus").value.trim();
  const prog = Math.max(0, Math.min(100, parseInt($("#adProg").value || "0", 10)));
  const description = $("#adDescription").value.trim();
  const list = $("#adList")
    .value.split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  if (!title || !due) {
    toast("제목/마감은 필수");
    return;
  }

  try {
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
        description: description,
        rubric_image: state.uploadedImageUrl
      }),
    });

    const data = await res.json();
    
    if (res.ok) {
      await fetchAssessments();
      closeAdd();
      renderRows();
      renderBuckets();
      toast("새 과제가 등록되었습니다");
    } else {
      toast(data.error || "등록 실패");
    }
  } catch (err) {
    toast("서버 오류: " + err.message);
  }
}

function closeAdd() {
  $("#addDrawer").classList.remove("show");
  $("#adTitle").value = "";
  $("#adDue").value = "";
  $("#adList").value = "";
  $("#adProg").value = "0";
  $("#adDescription").value = "";
  $("#adRubricImage").value = "";
  $("#imagePreviewContainer").style.display = "none";
  state.uploadedImageUrl = "";
}

/* ============================ 삭제 기능 ============================ */
async function deleteSelectedAssignments() {
  const selectedCheckboxes = document.querySelectorAll('.row input[type="checkbox"]:checked');
  
  if (selectedCheckboxes.length === 0) {
    toast('삭제할 과제를 선택해주세요.');
    return;
  }
  
  if (!confirm(`선택된 ${selectedCheckboxes.length}개의 과제를 삭제하시겠습니까?`)) {
    return;
  }
  
  const ids = Array.from(selectedCheckboxes).map(cb => {
    const row = cb.closest('.row');
    return parseInt(row.dataset.id);
  }).filter(id => !isNaN(id));
  
  if (ids.length === 0) {
    toast('유효한 ID를 찾을 수 없습니다.');
    return;
  }

  try {
    const res = await fetch('/api/assessments/bulk-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: ids })
    });

    const data = await res.json();
    
    if (res.ok) {
      toast(`${data.deleted}개의 과제가 삭제되었습니다.`);
      await fetchAssessments();
      renderRows();
      renderBuckets();
    } else {
      toast(data.error || '삭제 실패');
    }
  } catch (err) {
    toast('서버 오류: ' + err.message);
  }
}

/* ============================ Events ============================ */
function setupEvents() {
  // 필터
  $("#q").addEventListener("input", (e) => {
    state.query = e.target.value.trim();
    renderRows();
  });
  $("#status").addEventListener("change", (e) => {
    state.status = e.target.value;
    renderRows();
  });
  $("#sort").addEventListener("change", (e) => {
    state.sort = e.target.value;
    renderRows();
  });
  $("#clear").addEventListener("click", () => {
    state.query = "";
    state.status = "";
    $("#q").value = "";
    $("#status").value = "";
    renderRows();
  });

  // 탭
  $$("#tabs .tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$("#tabs .tab").forEach((b) => b.classList.remove("is-active"));
      btn.classList.add("is-active");
      state.subject = btn.dataset.subj;
      renderRows();
    });
  });

  // 디테일 닫기
  $("#dwClose").addEventListener("click", () => {
    $("#drawer").classList.remove("show");
  });

  // 추가 drawer
  const addBtn = $("#addBtn");
  const addDrawer = $("#addDrawer");
  const addCancel = $("#addCancel");
  const addCreate = $("#addCreate");
  const uploadBtn = $("#uploadRubricBtn");

  if (state.role === "admin" || state.role === "leader") {
    addBtn.classList.remove("hidden");
  }

  addBtn.addEventListener("click", () => {
    addDrawer.classList.add("show");
  });

  addCancel.addEventListener("click", () => {
    closeAdd();
  });

  addCreate.addEventListener("click", () => {
    createFromAdd();
  });

  if (uploadBtn) {
    uploadBtn.addEventListener("click", () => {
      uploadRubricImage();
    });
  }
}

// 사용자 역할 확인 및 관리자 UI 표시
function checkUserRole() {
  fetch('/api/user-info')
    .then(response => response.json())
    .then(data => {
      if (data.email === 'otaejin79@gmail.com') {
        document.getElementById('adminControls').classList.add('show');
        document.getElementById('roleBadge').textContent = '관리자';
        document.getElementById('roleBadge').classList.remove('hidden');
      }
    })
    .catch(error => {
      console.log('사용자 정보 확인 실패:', error);
    });
}

/* ============================ Init ============================ */
async function init() {
  await fetchUser();
  await fetchAssessments();
  renderHeader();
  renderRows();
  renderBuckets();
  setupEvents();
  checkUserRole();
}
document.addEventListener("DOMContentLoaded", init);