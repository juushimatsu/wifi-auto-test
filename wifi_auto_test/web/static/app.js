const API = '/api';
const WS_URL = `ws://${location.host}/ws/logs`;

let ws = null;

// --- WebSocket ---
function connectWS() {
  ws = new WebSocket(WS_URL);
  ws.onmessage = (e) => {
    appendLog(e.data);
  };
  ws.onclose = () => {
    setTimeout(connectWS, 3000);
  };
}

function appendLog(text) {
  const container = document.getElementById('log-container');
  const line = document.createElement('div');
  line.className = 'log-line';
  if (text.includes('[DEBUG]')) line.classList.add('debug');
  if (text.includes('[WARNING]')) line.classList.add('warning');
  if (text.includes('[ERROR]')) line.classList.add('error');
  line.textContent = text;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
  // Limit lines
  while (container.children.length > 500) {
    container.removeChild(container.firstChild);
  }
}

// --- Status ---
async function fetchStatus() {
  try {
    const r = await fetch(`${API}/status`);
    const s = await r.json();
    updateStatus(s);
  } catch (e) {
    console.error('status fetch error', e);
  }
}

function updateStatus(s) {
  const ind = document.getElementById('status-indicator');
  const txt = document.getElementById('status-text');
  if (s.running) {
    ind.className = s.paused ? 'indicator paused' : 'indicator running';
    txt.textContent = s.paused ? 'Пауза' : 'Работает';
  } else {
    ind.className = 'indicator stopped';
    txt.textContent = 'Остановлен';
  }

  document.getElementById('stat-scanned').textContent = s.total_scanned;
  document.getElementById('stat-success').textContent = s.total_success;
  document.getElementById('stat-failure').textContent = s.total_failure;
  document.getElementById('stat-queue').textContent = s.queue_size;

  const curEl = document.getElementById('current-network');
  if (s.current && s.current.bssid) {
    curEl.innerHTML = `<strong>${s.current.ssid || 'Hidden'}</strong><br>
      BSSID: ${s.current.bssid}<br>
      Channel: ${s.current.channel}`;
    curEl.className = 'network-card active';
  } else {
    curEl.innerHTML = '<p class="placeholder">Нет активного теста</p>';
    curEl.className = 'network-card';
  }
}

// --- Networks ---
async function fetchNetworks() {
  try {
    const r = await fetch(`${API}/networks`);
    const d = await r.json();
    renderNetworks(d.pending || [], d.successful || []);
  } catch (e) {
    console.error('networks fetch error', e);
  }
}

function renderNetworks(pending, successfulSet) {
  const tbody = document.getElementById('networks-tbody');
  tbody.innerHTML = '';

  const all = [...pending];
  const successMap = new Set(successfulSet);

  all.forEach((n, idx) => {
    const tr = document.createElement('tr');
    const isSuccess = successMap.has(n.bssid);
    const badge = isSuccess
      ? '<span class="badge success">success</span>'
      : '<span class="badge retry">pending</span>';

    tr.innerHTML = `
      <td>${n.ssid || '<i>hidden</i>'}</td>
      <td>${n.bssid}</td>
      <td>${n.channel}</td>
      <td>${n.signal_dbm} dBm</td>
      <td>${badge}</td>
      <td><button class="btn-prio" data-bssid="${n.bssid}">Приоритет</button></td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll('.btn-prio').forEach(btn => {
    btn.addEventListener('click', async () => {
      const bssid = btn.dataset.bssid;
      await fetch(`${API}/command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'prioritize', bssid }),
      });
    });
  });
}

// --- Controls ---
document.getElementById('btn-start').addEventListener('click', async () => {
  await fetch(`${API}/command`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'start' }),
  });
  fetchStatus();
});

document.getElementById('btn-stop').addEventListener('click', async () => {
  await fetch(`${API}/command`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'stop' }),
  });
  fetchStatus();
});

document.getElementById('btn-refresh').addEventListener('click', () => {
  fetchStatus();
  fetchNetworks();
});

// --- Init ---
connectWS();
fetchStatus();
fetchNetworks();
setInterval(fetchStatus, 2000);
setInterval(fetchNetworks, 5000);
