export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 處理班表讀寫 API
    if (url.pathname === '/api/schedule') {
      if (!env.SHIFT_KV) {
        return jsonResponse({ error: '尚未在 Cloudflare 後台綁定 SHIFT_KV 資料庫' }, 503);
      }

      const auth = verifyAndGetKey(request, env);
      if (!auth.ok) {
        return jsonResponse({ error: auth.message }, 401);
      }

      if (request.method === 'GET') {
        try {
          const rawData = await env.SHIFT_KV.get(auth.kvKey);
          return jsonResponse({ data: rawData ? JSON.parse(rawData) : null }, 200);
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
          await env.SHIFT_KV.put(auth.kvKey, JSON.stringify(payload));
          return jsonResponse({ success: true, updatedAt: payload.updatedAt }, 200);
        } catch (err) {
          return jsonResponse({ error: '寫入雲端資料失敗: ' + err.message }, 500);
        }
      }

      return jsonResponse({ error: '不支援的請求方法' }, 405);
    }

    // 其餘網址一律回傳 public 資料夾內的網頁畫面
    return env.ASSETS.fetch(request);
  }
};

function verifyAndGetKey(request, env) {
  const pin = (request.headers.get('X-Sync-Pin') || '').trim();

  if (!pin || pin.length < 4) {
    return { ok: false, message: '請輸入至少 4 個字元的通行碼' };
  }

  if (env.SYNC_PIN && pin !== env.SYNC_PIN) {
    return { ok: false, message: '通行碼錯誤，拒絕存取' };
  }

  return { ok: true, kvKey: `schedule_data_${pin}` };
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
