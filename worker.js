export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 檢查 KV 資料庫是否已綁定
    if (url.pathname.startsWith('/api/') && !env.SHIFT_KV) {
      return jsonResponse({ error: '尚未在 Cloudflare 後台綁定 SHIFT_KV 資料庫' }, 503);
    }

    // 0. 專屬登入與註冊頁面路由（任何情況下皆可直接開啟）
    if (url.pathname === '/login') {
      return htmlResponse(renderAuthPage());
    }

    // 1. 註冊新帳號 API
    if (url.pathname === '/api/register' && request.method === 'POST') {
      try {
        const body = await request.json();
        const username = normalizeUsername(body.username);
        const password = (body.password || '').trim();

        if (!isValidUsername(username)) {
          return jsonResponse({ error: '帳號名稱需為 2 到 20 個字元（支援中文、英文、數字或底線）' }, 400);
        }
        if (password.length < 4) {
          return jsonResponse({ error: '密碼長度至少需要 4 個字元' }, 400);
        }

        const authKey = `auth_${username}`;
        const existingUser = await env.SHIFT_KV.get(authKey);
        if (existingUser) {
          return jsonResponse({ error: '此帳號名稱已被註冊，請直接切換至「登入」或換一個名稱' }, 409);
        }

        const passwordHash = await hashPassword(password, username);
        await env.SHIFT_KV.put(authKey, JSON.stringify({
          username,
          passwordHash,
          createdAt: new Date().toISOString()
        }));

        const token = await createSignedSession(username, env);
        return jsonResponseWithCookie({ success: true, username }, token);
      } catch (err) {
        return jsonResponse({ error: '註冊失敗: ' + err.message }, 500);
      }
    }

    // 2. 登入現有帳號 API
    if (url.pathname === '/api/login' && request.method === 'POST') {
      try {
        const body = await request.json();
        const username = normalizeUsername(body.username);
        const password = (body.password || '').trim();

        if (!username || !password) {
          return jsonResponse({ error: '請輸入帳號與密碼' }, 400);
        }

        const rawAuth = await env.SHIFT_KV.get(`auth_${username}`);
        if (!rawAuth) {
          return jsonResponse({ error: '找不到此帳號，若為首次使用請切換至「建立新帳號」' }, 401);
        }

        const authData = JSON.parse(rawAuth);
        const inputHash = await hashPassword(password, username);
        if (inputHash !== authData.passwordHash) {
          return jsonResponse({ error: '密碼錯誤，請重新輸入' }, 401);
        }

        const token = await createSignedSession(username, env);
        return jsonResponseWithCookie({ success: true, username }, token);
      } catch (err) {
        return jsonResponse({ error: '登入失敗: ' + err.message }, 500);
      }
    }

    // 3. 登出鎖定 API
    if (url.pathname === '/api/logout' && request.method === 'POST') {
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          'Set-Cookie': 'shift_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
        }
      });
    }

    // 4. 個人專屬班表讀寫 API（依登入帳號隔離資料）
    if (url.pathname === '/api/schedule') {
      const username = await getAuthenticatedUser(request, env);
      if (!username) {
        return jsonResponse({ error: '登入已逾時，請重新登入' }, 401);
      }

      const dataKey = `data_${username}`;

      if (request.method === 'GET') {
        try {
          const rawData = await env.SHIFT_KV.get(dataKey);
          return jsonResponse({
            username,
            data: rawData ? JSON.parse(rawData) : null
          }, 200);
        } catch (err) {
          return jsonResponse({ error: '讀取雲端資料失敗: ' + err.message }, 500);
        }
      }

      if (request.method === 'POST') {
        try {
          const body = await request.json();
          const payload = {
            shiftRecords: body.shiftRecords || {},
            shiftPresets: body.shiftPresets || [],
            salaryConfig: body.salaryConfig || {},
            updatedAt: new Date().toISOString()
          };
          await env.SHIFT_KV.put(dataKey, JSON.stringify(payload));
          return jsonResponse({ success: true, username, updatedAt: payload.updatedAt }, 200);
        } catch (err) {
          return jsonResponse({ error: '寫入雲端資料失敗: ' + err.message }, 500);
        }
      }

      return jsonResponse({ error: '不支援的請求方法' }, 405);
    }

    // 5. 網頁門禁檢查：未登入者一律導向登入／註冊畫面
    const loggedInUser = await getAuthenticatedUser(request, env);
    if (!loggedInUser) {
      return htmlResponse(renderAuthPage());
    }

    // 6. 驗證通過，放行讀取 WORK 資料夾內的網頁
    return env.ASSETS.fetch(request);
  }
};

function normalizeUsername(raw) {
  return (raw || '').trim().toLowerCase();
}

function isValidUsername(name) {
  return /^[a-z0-9_\-\u4e00-\u9fa5]{2,20}$/i.test(name);
}

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${salt}::${password}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signHmac(message, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createSignedSession(username, env) {
  const secret = env.SESSION_SECRET || 'shift_schedule_hmac_key_2026';
  const expiresAt = Date.now() + 2592000 * 1000;
  const payload = `${encodeURIComponent(username)}.${expiresAt}`;
  const signature = await signHmac(payload, secret);
  return `${payload}.${signature}`;
}

function getSessionToken(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/(?:^|;\s*)shift_session=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : '';
}

async function getAuthenticatedUser(request, env) {
  const token = getSessionToken(request);
  if (!token) return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [encodedUser, expiresAtStr, signature] = parts;
  if (Date.now() > Number(expiresAtStr)) return null;

  const secret = env.SESSION_SECRET || 'shift_schedule_hmac_key_2026';
  const expectedSig = await signHmac(`${encodedUser}.${expiresAtStr}`, secret);
  if (signature !== expectedSig) return null;

  return decodeURIComponent(encodedUser);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json;charset=UTF-8',
      'Cache-Control': 'no-store'
    }
  });
}

function jsonResponseWithCookie(data, token) {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: {
      'Content-Type': 'application/json;charset=UTF-8',
      'Cache-Control': 'no-store',
      'Set-Cookie': `shift_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`
    }
  });
}

function htmlResponse(html) {
  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'no-store'
    }
  });
}

function renderAuthPage() {
  return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登入或建立個人班表帳號</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen flex items-center justify-center p-4">
  <div class="bg-slate-800 border border-slate-700 rounded-2xl max-w-sm w-full p-6 shadow-2xl space-y-5">
    <div class="text-center space-y-1">
      <div class="text-4xl mb-2">⏱️</div>
      <h1 class="text-lg font-bold text-white">個人班表與薪資計算系統</h1>
      <p class="text-xs text-slate-400">每個人擁有獨立加密雲端空間，資料互不干擾</p>
    </div>

    <div class="grid grid-cols-2 gap-1 p-1 rounded-xl bg-slate-900/80 border border-slate-700 text-xs font-bold">
      <button type="button" id="tabLogin" onclick="switchMode('login')"
        class="py-2 rounded-lg bg-indigo-600 text-white transition">
        登入現有帳號
      </button>
      <button type="button" id="tabRegister" onclick="switchMode('register')"
        class="py-2 rounded-lg text-slate-400 hover:text-white transition">
        建立新帳號
      </button>
    </div>

    <form id="authForm" class="space-y-3">
      <div>
        <label class="block text-xs font-semibold text-slate-300 mb-1">個人帳號 / 暱稱</label>
        <input type="text" id="usernameInput" required autofocus placeholder="請輸入英文、數字或中文暱稱"
          class="w-full px-3.5 py-2.5 text-sm rounded-xl border border-slate-600 bg-slate-700 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500">
      </div>

      <div>
        <label class="block text-xs font-semibold text-slate-300 mb-1">專屬密碼（至少 4 碼）</label>
        <input type="password" id="passwordInput" required placeholder="請輸入您的專屬密碼"
          class="w-full px-3.5 py-2.5 text-sm rounded-xl border border-slate-600 bg-slate-700 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500">
      </div>

      <p id="hintText" class="text-[11px] text-slate-400">
        輸入您設定過的帳號與密碼，即可載入雲端班表。
      </p>

      <p id="errMsg" class="text-xs text-rose-400 bg-rose-950/40 border border-rose-900/60 px-3 py-2 rounded-lg hidden"></p>

      <button type="submit" id="submitBtn"
        class="w-full py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-bold transition shadow-md">
        登入進入系統
      </button>
    </form>
  </div>

  <script>
    let currentMode = 'login';

    function switchMode(mode) {
      currentMode = mode;
      const tabLogin = document.getElementById('tabLogin');
      const tabRegister = document.getElementById('tabRegister');
      const submitBtn = document.getElementById('submitBtn');
      const hintText = document.getElementById('hintText');
      const errEl = document.getElementById('errMsg');
      errEl.classList.add('hidden');

      if (mode === 'login') {
        tabLogin.className = 'py-2 rounded-lg bg-indigo-600 text-white transition';
        tabRegister.className = 'py-2 rounded-lg text-slate-400 hover:text-white transition';
        submitBtn.innerText = '登入進入系統';
        hintText.innerText = '輸入您設定過的帳號與密碼，即可載入雲端班表。';
      } else {
        tabRegister.className = 'py-2 rounded-lg bg-indigo-600 text-white transition';
        tabLogin.className = 'py-2 rounded-lg text-slate-400 hover:text-white transition';
        submitBtn.innerText = '建立帳號並進入';
        hintText.innerText = '首次使用請建立一組專屬帳號與密碼，之後換手機登入也能同步。';
      }
    }

    document.getElementById('authForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('usernameInput').value.trim();
      const password = document.getElementById('passwordInput').value.trim();
      const errEl = document.getElementById('errMsg');
      const btn = document.getElementById('submitBtn');

      errEl.classList.add('hidden');
      btn.disabled = true;
      btn.innerText = currentMode === 'login' ? '登入中...' : '建立中...';

      const endpoint = currentMode === 'login' ? '/api/login' : '/api/register';

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();

        if (!res.ok) {
          errEl.innerText = data.error || '操作失敗，請檢查輸入內容';
          errEl.classList.remove('hidden');
          btn.disabled = false;
          btn.innerText = currentMode === 'login' ? '登入進入系統' : '建立帳號並進入';
          return;
        }

        window.location.replace('/');
      } catch (err) {
        errEl.innerText = '網路連線失敗，請稍後再試';
        errEl.classList.remove('hidden');
        btn.disabled = false;
        btn.innerText = currentMode === 'login' ? '登入進入系統' : '建立帳號並進入';
      }
    });
  </script>
</body>
</html>`;
}
