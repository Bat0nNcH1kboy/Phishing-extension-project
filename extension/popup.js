const API_URL = 'http://localhost:5001/api/check';
const REQUEST_TIMEOUT_MS = 7000;

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function statusClass(data) {
  if (data.verdict === 'phishing') return 'phishing';
  if (data.risk_level === 'medium') return 'suspicious';
  if (data.verdict === 'safe') return 'safe';
  return 'unknown';
}

function statusText(data) {
  if (data.verdict === 'phishing') return 'Обнаружен риск фишинга';
  if (data.risk_level === 'medium') return 'Сайт требует внимания';
  if (data.verdict === 'safe') return 'Сайт выглядит безопасным';
  return 'Не удалось определить статус';
}

function renderResult(data) {
  const result = document.getElementById('result');
  const details = document.getElementById('details');
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  result.className = `status ${statusClass(data)}`;
  result.textContent = statusText(data);
  details.innerHTML = `
    <div><b>Источник:</b> ${escapeHtml(data.source || 'unknown')}</div>
    <div><b>Уверенность:</b> ${Math.round(Number(data.confidence || 0) * 100)}%</div>
    <div><b>Домен:</b> ${escapeHtml(data.domain || '-')}</div>
    <div><b>Причины:</b>${reasons.length ? `<ul>${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')}</ul>` : ' не выявлены'}</div>
  `;
}

async function getCurrentTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab && tab.url ? tab.url : '';
}

async function parseJsonResponse(response) {
  try {
    return await response.json();
  } catch (error) {
    return {
      verdict: 'unknown',
      source: 'client',
      confidence: 0,
      risk_level: 'unknown',
      reasons: [`backend вернул HTTP ${response.status}, но тело ответа не является JSON`],
      domain: ''
    };
  }
}

async function postWithTimeout(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function checkCurrentTab() {
  const result = document.getElementById('result');
  const details = document.getElementById('details');
  const urlBox = document.getElementById('url');
  const button = document.getElementById('checkBtn');

  result.className = 'status unknown';
  result.textContent = 'Проверка...';
  details.textContent = '';
  button.disabled = true;

  try {
    const url = await getCurrentTabUrl();
    urlBox.textContent = url || 'URL не определён';
    if (!url) {
      renderResult({
        verdict: 'unknown',
        source: 'client',
        confidence: 0,
        risk_level: 'unknown',
        reasons: ['не удалось получить URL активной вкладки'],
        domain: ''
      });
      return;
    }

    const response = await postWithTimeout(url);
    const data = await parseJsonResponse(response);
    renderResult(data);
  } catch (error) {
    result.className = 'status unknown';
    result.textContent = error.name === 'AbortError'
      ? 'Backend не ответил за 7 секунд'
      : 'Ошибка подключения к backend';
    details.textContent = error.name === 'AbortError'
      ? 'Проверьте, что Flask-сервер запущен на http://127.0.0.1:5001, и повторите проверку.'
      : String(error);
  } finally {
    button.disabled = false;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('checkBtn').addEventListener('click', checkCurrentTab);
  checkCurrentTab();
});
