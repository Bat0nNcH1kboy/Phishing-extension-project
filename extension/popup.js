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

function sourceText(value) {
  const map = {
    database: 'база',
    hybrid: 'гибрид',
    ml: 'модель',
    ml_textured: 'модель',
    heuristic: 'эвристика',
    client: 'клиент',
    error: 'ошибка',
    unknown: 'неизвестно'
  };
  return map[value] || value || 'неизвестно';
}

function riskText(value) {
  const map = {
    low: 'низкий',
    medium: 'средний',
    high: 'высокий',
    unknown: 'неизвестно'
  };
  return map[value] || value || 'неизвестно';
}

function reasonText(value) {
  const map = {
    'учебная запись безопасного домена из расширенной базы': 'Безопасный домен из базы'
  };
  return map[value] || value;
}

function technicalDetails(data) {
  return {
    dns: data.dns || data.checks || {},
    texture_analysis: data.texture_analysis || data.texture || data.url_texture || {},
    ml_probability: data.ml_probability ?? null,
    heuristic_score: data.heuristic_score ?? null,
    phishing_probability: data.phishing_probability ?? null
  };
}

function checksText(data) {
  const details = technicalDetails(data);
  const checks = details.dns;

  const dnsOk =
    checks.exists === true ||
    checks.dns_resolvable === true;

  const dnsFailed =
    checks.checked === false ||
    checks.dns_checked === false;

  if (dnsOk) {
    return 'домен существует, подозрительных маркеров не найдено';
  }

  if (dnsFailed) {
    return 'DNS-проверка не выполнялась';
  }

  return 'проверка выполнена';
}

function textureText(data) {
  const details = technicalDetails(data);
  const texture = details.texture_analysis || {};

  const loginMarkers = Number(texture.login_markers || texture.login_marker_count || 0);
  const typoBrands = Number(texture.typo_brands || texture.typo_brand_count || texture.brand_typo_markers || 0);

  if (loginMarkers === 0 && typoBrands === 0) {
    return 'признаков подмены бренда и login-маркеров не обнаружено';
  }

  const parts = [];

  if (loginMarkers > 0) {
    parts.push(`обнаружены login-маркеры: ${loginMarkers}`);
  }

  if (typoBrands > 0) {
    parts.push(`обнаружены признаки подмены бренда: ${typoBrands}`);
  }

  return parts.join(', ');
}

function renderResult(data) {
  const result = document.getElementById('result');
  const details = document.getElementById('details');
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  const technical = technicalDetails(data);

  result.className = `status ${statusClass(data)}`;
  result.textContent = statusText(data);

  details.innerHTML = `
    <div>
      <span class="pill"><b>Источник:</b> ${escapeHtml(sourceText(data.source))}</span>
      <span class="pill"><b>Риск:</b> ${escapeHtml(riskText(data.risk_level))}</span>
    </div>
    <div><b>Уверенность:</b> ${percent(data.confidence)} · <b>Вероятность фишинга:</b> ${percent(technical.phishing_probability)}</div>
    <div><b>Домен:</b> ${escapeHtml(data.domain || '-')}</div>
    <div><b>Проверки:</b> ${escapeHtml(checksText(data))}</div>
    <div class="texture-line"><b>Дополнительный анализ URL:</b> ${escapeHtml(textureText(data))}</div>
    <div><b>Причины:</b>${reasons.length ? `<ul>${reasons.map((reason) => `<li>${escapeHtml(reasonText(reason))}</li>`).join('')}</ul>` : ' не выявлены'}</div>
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
      ml_probability: 0,
      heuristic_score: 0,
      risk_level: 'unknown',
      reasons: [`backend вернул HTTP ${response.status}, но тело ответа не является JSON`],
      domain: '',
      checks: {},
      texture_analysis: {}
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
        verdict: 'unknown',
        source: 'client',
        confidence: 0,
        phishing_probability: 0,
        ml_probability: 0,
        heuristic_score: 0,
        risk_level: 'unknown',
        reasons: ['URL не указан'],
        domain: '',
        checks: {},
        texture_analysis: {}
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