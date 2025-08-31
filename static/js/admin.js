      const toast = (m) => {
        const t = document.getElementById('toast');
        t.textContent = m;
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 1800);
      };
      const $ = (id) => document.getElementById(id);
      const show = (p) => {
        ['overview', 'users', 'classes', 'assign'].forEach((x) =>
          $('page-' + x).classList.add('hidden')
        );
        $('page-' + p).classList.remove('hidden');
        document
          .querySelectorAll('#nav a')
          .forEach((a) => a.classList.toggle('active', a.dataset.page === p));
      };

      // 네비
      document.querySelectorAll('#nav a').forEach((a) => {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          show(a.dataset.page);
        });
      });

      // API
      async function api(path, opt = {}) {
        const res = await fetch(path, {
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          ...opt,
        });
        if (!res.ok) {
          let msg = await res.text();
          try {
            const j = JSON.parse(msg);
            msg = j.error || msg;
          } catch {}
          throw new Error(msg || res.statusText);
        }
        if (res.status === 204) return null;
        return res.json();
      }

      // 대시보드
      async function loadOverview() {
        const j = await api('/admin/api/overview');
        $('stat-users').textContent = j.users;
        $('stat-classes').textContent = j.classes;
        $('stat-two').textContent = j.classes_with_two_leaders;
      }
      $('btn-refresh').onclick = () => loadAll();

      // 계정 관리
      let cacheUsers = [],
        cacheClasses = [];
      function renderUsers(list) {
        const tb = $('tbl-users').querySelector('tbody');
        tb.innerHTML = '';
        list.forEach((u) => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
      <td>${u.name || ''}</td>
      <td>${u.email}</td>
      <td>
        <select data-role="${u.email}">
          <option value="student" ${
            u.role !== 'leader' ? 'selected' : ''
          }>student</option>
          <option value="leader" ${
            u.role === 'leader' ? 'selected' : ''
          }>leader</option>
        </select>
      </td>
      <td>
        <select data-class="${u.email}">
          <option value="">-</option>
          ${cacheClasses
            .map(
              (c) =>
                `<option value="${c.id}" ${
                  u.class_id === c.id ? 'selected' : ''
                }>${c.name}</option>`
            )
            .join('')}
        </select>
      </td>
      <td>${u.phone || ''}</td>
      <td class="row">
        <button class="primary" data-save="${u.email}">반/역할 저장</button>
        <button class="danger" data-del="${u.email}">계정 삭제</button>
      </td>`;
          tb.appendChild(tr);
        });
      }
      $('tbl-users').onclick = async (e) => {
        const email = e.target.getAttribute('data-del');
        const saveE = e.target.getAttribute('data-save');
        if (email) {
          if (!confirm('정말 이 계정을 삭제하시겠습니까?')) return;
          try {
            await api('/admin/api/users/delete', {
              method: 'POST',
              body: JSON.stringify({ email }),
            });
            toast('삭제되었습니다');
            await loadUsers();
            await loadOverview();
          } catch (err) {
            toast(err.message);
          }
        }
        if (saveE) {
          const role = document.querySelector(
            `select[data-role="${saveE}"]`
          ).value;
          const cls =
            document.querySelector(`select[data-class="${saveE}"]`).value ||
            null;
          try {
            await api('/admin/api/users/assign', {
              method: 'POST',
              body: JSON.stringify({
                email: saveE,
                role,
                class_id: cls ? Number(cls) : null,
              }),
            });
            toast('저장되었습니다');
            await loadUsers();
            await loadAssignTable();
            await loadOverview();
          } catch (err) {
            toast(err.message);
          }
        }
      };
      $('q-user').addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase();
        const f = cacheUsers.filter(
          (u) =>
            (u.name || '').toLowerCase().includes(q) ||
            (u.email || '').toLowerCase().includes(q) ||
            (u.class_name || '').toLowerCase().includes(q)
        );
        renderUsers(f);
      });
      async function loadUsers() {
        cacheUsers = await api('/admin/api/users');
        renderUsers(cacheUsers);
      }

      // 학급 관리
      function renderClasses(list) {
        const tb = $('tbl-classes').querySelector('tbody');
        tb.innerHTML = '';
        list.forEach((c) => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
      <td>${c.id}</td>
      <td><input value="${c.name}" data-cname="${c.id}" /></td>
      <td><input value="${c.grade || ''}" data-cgrade="${
            c.id
          }" style="width:100px" /></td>
      <td class="row">
        <button class="primary" data-csave="${c.id}">수정</button>
        <button class="danger" data-cdel="${c.id}">삭제</button>
      </td>`;
          tb.appendChild(tr);
        });
      }
      $('btn-add-class').onclick = async () => {
        const name = $('new-class-name').value.trim();
        const grade = $('new-class-grade').value.trim() || null;
        if (!name) {
          toast('학급명을 입력하십시오');
          return;
        }
        try {
          await api('/admin/api/classes', {
            method: 'POST',
            body: JSON.stringify({ name, grade }),
          });
          $('new-class-name').value = '';
          $('new-class-grade').value = '';
          toast('추가되었습니다');
          await loadClasses();
          await loadAssignTable();
          await loadOverview();
        } catch (err) {
          toast(err.message);
        }
      };
      $('tbl-classes').onclick = async (e) => {
        const cid = e.target.getAttribute('data-csave');
        const did = e.target.getAttribute('data-cdel');
        if (cid) {
          const name = document
            .querySelector(`input[data-cname="${cid}"]`)
            .value.trim();
          const grade =
            document
              .querySelector(`input[data-cgrade="${cid}"]`)
              .value.trim() || null;
          if (!name) {
            toast('학급명은 비울 수 없습니다');
            return;
          }
          try {
            await api(`/admin/api/classes/${cid}`, {
              method: 'PATCH',
              body: JSON.stringify({ name, grade }),
            });
            toast('수정되었습니다');
            await loadClasses();
            await loadAssignTable();
          } catch (err) {
            toast(err.message);
          }
        }
        if (did) {
          if (!confirm('해당 학급을 삭제하시겠습니까? (소속 해제됨)')) return;
          try {
            await api(`/admin/api/classes/${did}`, { method: 'DELETE' });
            toast('삭제되었습니다');
            await loadClasses();
            await loadUsers();
            await loadAssignTable();
            await loadOverview();
          } catch (err) {
            toast(err.message);
          }
        }
      };
      async function loadClasses() {
        cacheClasses = await api('/admin/api/classes');
        renderClasses(cacheClasses);
      }

      // 반장 배치(2인)
      function leaderOptions(selectedEmail) {
        return ['<option value="">-</option>']
          .concat(
            cacheUsers.map(
              (u) =>
                `<option value="${u.email}" ${
                  u.email === selectedEmail ? 'selected' : ''
                }>${u.name || u.email}${
                  u.class_name ? ` · ${u.class_name}` : ''
                }</option>`
            )
          )
          .join('');
      }
      async function loadAssignTable() {
        // 서버에 “학급별 현재 반장” 목록 API가 별도로 없으므로, users 리스트에서 role/class로 계산
        const tb = $('tbl-assign').querySelector('tbody');
        tb.innerHTML = '';
        const byClass = new Map(
          cacheClasses.map((c) => [c.id, { class: c, leaders: [] }])
        );
        cacheUsers.forEach((u) => {
          if (u.role === 'leader' && u.class_id) {
            const bucket = byClass.get(u.class_id);
            if (bucket) bucket.leaders.push(u);
          }
        });
        cacheClasses.forEach((c) => {
          const cur = byClass.get(c.id).leaders;
          const l0 = cur[0]?.email || '';
          const l1 = cur[1]?.email || '';
          const tr = document.createElement('tr');
          tr.innerHTML = `
      <td>${c.name}</td>
      <td><select id="ass-${c.id}-0">${leaderOptions(l0)}</select></td>
      <td><select id="ass-${c.id}-1">${leaderOptions(l1)}</select></td>
      <td><button class="primary" data-save="${c.id}">저장</button></td>`;
          tb.appendChild(tr);
        });
      }
      $('tbl-assign').onclick = async (e) => {
        const cid = e.target.getAttribute('data-save');
        if (!cid) return;
        const v0 = document.getElementById(`ass-${cid}-0`).value || null;
        const v1 = document.getElementById(`ass-${cid}-1`).value || null;
        const chosen = Array.from(new Set([v0, v1].filter(Boolean)));
        if (chosen.length > 2) {
          toast('최대 2명만 지정할 수 있습니다');
          return;
        }
        try {
          await api(`/admin/api/classes/${cid}/assign`, {
            method: 'POST',
            body: JSON.stringify({ emails: chosen }),
          });
          toast('배치 저장됨');
          await loadUsers();
          await loadAssignTable();
          await loadOverview();
        } catch (err) {
          toast(err.message);
        }
      };

      // 초기화
      async function loadAll() {
        await loadOverview();
        await loadClasses();
        await loadUsers();
        await loadAssignTable();
      }
      loadAll();