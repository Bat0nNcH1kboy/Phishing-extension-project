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
  if (data.verdict === 'phishing' || data.risk_level === 'high') return 'phishing';
  if (data.risk_level === 'medium') return 'suspicious';
  if (data.verdict === 'safe') return 'safe';
  return 'unknown';
}

function statusText(data) {
  if (data.verdict === 'phishing' || data.risk_level === 'high') return 'Обнаружен высокий риск фишинга';
  if (data.risk_level === 'medium') return 'Сайт требует внимания';
  if (data.verdict === 'safe') return 'Сайт выглядит безопасным';
  return 'Не удалось определить статус';
}

function percent(value) {
  return `${Math.round(Number(value || 0) * 100)}%`;
}

function renderResult(data) {
  const result = document.getElementById('result');
  const details = document.getElementById('details');
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  const checks = data.checks || {};
  const texture = data.texture_analysis || {};
  const textureText = texture.enabled
    ? `токены ${escapeHtml(texture.token_count || 0)}, переходы ${escapeHtml(texture.charclass_transitions || 0)}, login-маркеры ${escapeHtml(texture.login_markers || 0)}, typo-бренды ${escapeHtml(texture.brand_typo_markers || 0)}`
    : 'не передан backend';
  const dnsText = checks.dns_checked
    ? (checks.dns_resolvable === true ? 'DNS: домен существует' : checks.dns_resolvable === false ? 'DNS: домен не подтверждён' : 'DNS: нет точного ответа')
    : 'DNS: не выполнялась';

  result.className = `status ${statusClass(data)}`;
  result.textContent = statusText(data);
  details.innerHTML = `
    <div><span class="pill"><b>Источник:</b> ${escapeHtml(data.source || 'unknown')}</span><span class="pill"><b>Риск:</b> ${escapeHtml(data.risk_level || 'unknown')}</span></div>
    <div><b>Уверенность:</b> ${percent(data.confidence)} · <b>Вероятность фишинга:</b> ${percent(data.phishing_probability)}</div>
    <div><b>Домен:</b> ${escapeHtml(data.domain || '-')}</div>
    <div><b>Проверки:</b> <span class="muted">${escapeHtml(dnsText)}</span>${checks.ml_probability !== undefined && checks.ml_probability !== null ? ` · ML ${percent(checks.ml_probability)} · эвристика ${percent(checks.heuristic_score)}` : ''}${checks.url_texture_model ? ' · n-gram текстуры включены' : ''}</div>
    <div class="texture-line"><b>Текстурный профиль URL:</b> <span class="muted">${textureText}</span></div>
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
      phishing_probability: 0,
      risk_level: 'unknown',
      reasons: [`backend вернул HTTP ${response.status}, но тело ответа не является JSON`],
      domain: '',
      checks: {}
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

function setBusy(isBusy) {
  document.getElementById('checkCurrentBtn').disabled = isBusy;
  document.getElementById('checkManualBtn').disabled = isBusy;
}

async function checkUrl(url) {
  const result = document.getElementById('result');
  const details = document.getElementById('details');
  result.className = 'status unknown';
  result.textContent = 'Проверка...';
  details.textContent = '';
  setBusy(true);

  try {
    if (!url) {
      renderResult({
        verdict: 'unknown', source: 'client', confidence: 0, phishing_probability: 0,
        risk_level: 'unknown', reasons: ['URL не указан'], domain: '', checks: {}
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
    setBusy(false);
  }
}

async function checkCurrentTab() {
  const manual = document.getElementById('manualUrl');
  const url = await getCurrentTabUrl();
  manual.value = url || '';
  await checkUrl(url);
}

async function checkManualUrl() {
  const url = document.getElementById('manualUrl').value.trim();
  await checkUrl(url);
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('checkCurrentBtn').addEventListener('click', checkCurrentTab);
  document.getElementById('checkManualBtn').addEventListener('click', checkManualUrl);
  checkCurrentTab();
});
