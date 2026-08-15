let latestRunId = null;
let latestStatus = null;
let latestStartTime = null;
let selectedPiiTypes = [];

let elapsedTimerId = null;
let elapsedStartMs = null;

let allFindings = [];
let filteredFindings = [];
let findingsPage = 1;
const FINDINGS_PAGE_SIZE = 10;

let allHistory = [];
let historyPage = 1;
const HISTORY_PAGE_SIZE = 10;

let browseCurrentPath = '';
let browseParentPath = null;

const TYPE_LABELS = {
  CARD_NUMBER: 'Card Number',
  AADHAAR_NUMBER: 'Aadhaar Number',
  PAN_NUMBER: 'PAN Number'
};

function friendlyType(t) {
  return TYPE_LABELS[t] || t;
}

function formatTimestamp(iso) {
  if (!iso) return '–';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const day = String(d.getDate()).padStart(2, '0');
  const month = months[d.getMonth()];
  const year = d.getFullYear();
  let hours = d.getHours();
  const minutes = String(d.getMinutes()).padStart(2, '0');
  const ampm = hours >= 12 ? 'PM' : 'AM';
  hours = hours % 12;
  if (hours === 0) hours = 12;
  return `${day} ${month} ${year}, ${hours}:${minutes} ${ampm}`;
}

function formatDurationMs(ms) {
  if (ms == null || isNaN(ms) || ms < 0) return '00:00:00.000';
  const totalMs = Math.floor(ms);
  const totalSec = Math.floor(totalMs / 1000);
  const millis = String(totalMs % 1000).padStart(3, '0');
  const h = String(Math.floor(totalSec / 3600)).padStart(2, '0');
  const m = String(Math.floor((totalSec % 3600) / 60)).padStart(2, '0');
  const s = String(totalSec % 60).padStart(2, '0');
  return `${h}:${m}:${s}.${millis}`;
}

function locationOf(filePath, fileName) {
  if (!filePath) return '-';
  if (fileName && filePath.endsWith(fileName)) {
    return filePath.slice(0, filePath.length - fileName.length).replace(/[\\/]$/, '');
  }
  const idx = Math.max(filePath.lastIndexOf('\\'), filePath.lastIndexOf('/'));
  return idx > -1 ? filePath.slice(0, idx) : filePath;
}

function csvEscape(value) {
  const s = (value === null || value === undefined) ? '' : String(value);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

/* ---------- browse modal ---------- */
async function openBrowseModal(startPath) {
  document.getElementById('browse-modal-overlay').hidden = false;
  await loadBrowsePath(startPath || document.getElementById('scan-path-input').value.trim());
}

function closeBrowseModal() {
  document.getElementById('browse-modal-overlay').hidden = true;
}

async function loadBrowsePath(path) {
  try {
    const url = path ? `/api/scans/browse?path=${encodeURIComponent(path)}` : '/api/scans/browse';
    const res = await fetch(url);
    const data = await res.json();
    browseCurrentPath = data.currentPath;
    browseParentPath = data.parentPath;

    document.getElementById('browse-current-path').textContent = browseCurrentPath || 'Drives';

    const list = document.getElementById('browse-folder-list');
    list.innerHTML = '';

    if (browseParentPath !== null) {
      const up = document.createElement('div');
      up.className = 'modal-up-row';
      up.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 19V5M5 12l7-7 7 7"/></svg> .. (Up)`;
      up.onclick = () => loadBrowsePath(browseParentPath);
      list.appendChild(up);
    }

    if (data.folders.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'modal-empty';
      empty.textContent = 'No subfolders here';
      list.appendChild(empty);
    } else {
      data.folders.forEach(f => {
        const row = document.createElement('div');
        row.className = 'modal-folder-row';
        row.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/></svg> ${f.name}`;
        row.onclick = () => loadBrowsePath(f.path);
        list.appendChild(row);
      });
    }
  } catch (e) {
    console.error('Failed to browse', e);
  }
}

document.getElementById('browse-btn').onclick = () => openBrowseModal();
document.getElementById('browse-modal-close').onclick = closeBrowseModal;
document.getElementById('browse-modal-cancel').onclick = closeBrowseModal;
document.getElementById('browse-modal-overlay').addEventListener('click', (e) => {
  if (e.target.id === 'browse-modal-overlay') closeBrowseModal();
});
document.getElementById('browse-modal-select').onclick = () => {
  if (browseCurrentPath) {
    document.getElementById('scan-path-input').value = browseCurrentPath;
  }
  closeBrowseModal();
};

/* ---------- header actions ---------- */
document.getElementById('settings-btn').onclick = () =>
    document.getElementById('settings-section').scrollIntoView({ behavior: 'smooth' });
document.getElementById('detection-rules-btn').onclick = () =>
    document.getElementById('detection-rules-section').scrollIntoView({ behavior: 'smooth' });
document.getElementById('configure-filters-btn').onclick = (e) => {
  e.stopPropagation();
  document.getElementById('settings-section').scrollIntoView({ behavior: 'smooth' });
};
document.getElementById('export-report-btn').onclick = () => {
  if (allHistory.length === 0) {
    alert('No completed scans to export yet.');
    return;
  }
  const latest = allHistory.find(r => r.status === 'COMPLETED');
  if (!latest) {
    alert('No completed scan report available yet.');
    return;
  }
  window.location.href = `/api/scans/${latest.runId}/download`;
};

document.getElementById('export-findings-btn').onclick = () => {
  if (filteredFindings.length === 0) {
    alert('No findings match the current filters to export.');
    return;
  }

  const headers = ['File Name', 'File Path', 'PII Type', 'Risk Level', 'Masked Value',
    'Scan Timestamp', 'File Created', 'File Modified'];
  const rows = filteredFindings.map(f => [
    csvEscape(f.fileName),
    csvEscape(f.filePath),
    csvEscape(friendlyType(f.dataType)),
    csvEscape(f.riskLevel),
    csvEscape(f.maskedValue),
    csvEscape(formatTimestamp(f.scanTimestamp)),
    csvEscape(formatTimestamp(f.fileCreationTime)),
    csvEscape(formatTimestamp(f.fileModifiedTime))
  ].join(','));

  const csvContent = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `findings-export-${Date.now()}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

/* ---------- PII chip selector (scan config) ---------- */
async function loadDataTypes() {
  try {
    const res = await fetch('/api/scans/data-types');
    const types = await res.json();

    const group = document.getElementById('pii-chip-group');
    group.innerHTML = '';
    types.forEach(t => {
      const chip = document.createElement('div');
      chip.className = 'pii-chip';
      chip.dataset.type = t;
      chip.innerHTML = `<span class="check"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span><span>${friendlyType(t)}</span>`;
      chip.onclick = () => togglePiiChip(chip, t);
      group.appendChild(chip);
    });

    const typeFilter = document.getElementById('type-filter');
    types.forEach(t => {
      const opt = document.createElement('option');
      opt.value = t;
      opt.textContent = friendlyType(t);
      typeFilter.appendChild(opt);
    });
  } catch (e) {
    console.error('Failed to load data types', e);
  }
}

function togglePiiChip(chip, type) {
  const idx = selectedPiiTypes.indexOf(type);
  if (idx > -1) {
    selectedPiiTypes.splice(idx, 1);
    chip.classList.remove('selected');
  } else {
    selectedPiiTypes.push(type);
    chip.classList.add('selected');
  }
}

/* ---------- status badge / panel ---------- */
function setBadge(cls, text) {
  const badge = document.getElementById('status-badge');
  badge.className = 'badge ' + cls;
  badge.textContent = text;
}

function setStatusPanel(cls, heading, subheading) {
  const iconWrap = document.getElementById('status-icon-wrap');
  iconWrap.className = 'status-icon-wrap ' + cls;
  document.getElementById('status-heading').textContent = heading;
  document.getElementById('status-subheading').textContent = subheading;
}

/* ---------- elapsed timer ----------
   Starts ticking immediately (client-side) rather than waiting on the
   next poll cycle, syncs to the server's real startTime once confirmed,
   and freezes the instant the run is no longer RUNNING. */
function startElapsedTicker(startTimeIso) {
  elapsedStartMs = startTimeIso ? new Date(startTimeIso).getTime() : Date.now();
  tickElapsed();
  if (!elapsedTimerId) {
    elapsedTimerId = setInterval(tickElapsed, 1000);
  }
}

function tickElapsed() {
  if (elapsedStartMs == null) return;
  const formatted = formatDurationMs(Date.now() - elapsedStartMs);
  document.getElementById('status-elapsed').textContent = formatted;
  document.getElementById('summary-duration').textContent = formatted;
}

function stopElapsedTicker(finalMs) {
  if (elapsedTimerId) {
    clearInterval(elapsedTimerId);
    elapsedTimerId = null;
  }
  const formatted = formatDurationMs(finalMs);
  document.getElementById('status-elapsed').textContent = formatted;
  document.getElementById('summary-duration').textContent = formatted;
}

/* ---------- polling: current run ---------- */
async function pollCurrent() {
  try {
    const res = await fetch('/api/scans/current');

    if (res.status === 204) {
      // No "current" run from the backend's point of view. This can mean
      // either nothing has ever run (elapsed is already 00:00:00 from
      // page load), or the last run just finished and dropped out of
      // "current". Either way, leave the elapsed/duration display as-is —
      // it should only change on a fresh triggerScan() call or a page
      // refresh, never just because polling stopped seeing a run.
      if (elapsedTimerId) {
        tickElapsed(); // lock in the most accurate final value before stopping
        clearInterval(elapsedTimerId);
        elapsedTimerId = null;
      }
      setBadge('idle', 'Scanner Ready');
      setStatusPanel('', 'Idle', 'No scan running');
      document.getElementById('progress-track').classList.remove('indeterminate');
      document.getElementById('progress-fill').style.width = '0%';
      document.getElementById('current-file').textContent = '–';
      latestStatus = null;
      latestStartTime = null;
      return;
    }

    const data = await res.json();
    latestRunId = data.runId;
    latestStatus = data.status;
    latestStartTime = data.startTime;

    const progressTrack = document.getElementById('progress-track');
    const progressFill = document.getElementById('progress-fill');

    if (data.status === 'RUNNING') {
      setBadge('running', 'Scanning…');
      setStatusPanel('running', 'Running', 'Scan in progress');
      progressTrack.classList.add('indeterminate');
      document.getElementById('current-file').textContent = data.currentFile || '–';
      startElapsedTicker(data.startTime);
    } else if (data.status === 'FAILED') {
      setBadge('failed', 'Failed');
      setStatusPanel('failed', 'Failed', 'Scan encountered an error');
      progressTrack.classList.remove('indeterminate');
      progressFill.style.width = '100%';
      document.getElementById('current-file').textContent = '–';
    } else {
      setBadge('completed', 'Completed');
      setStatusPanel('completed', 'Completed', 'Scan completed successfully');
      progressTrack.classList.remove('indeterminate');
      progressFill.style.width = '100%';
      document.getElementById('current-file').textContent = '–';
    }

    document.getElementById('dash-critical').textContent = data.criticalCount;
    document.getElementById('dash-medium').textContent = data.mediumCount;
    document.getElementById('dash-normal').textContent = data.normalCount;
    document.getElementById('dash-scanned').textContent = data.filesScanned;
    document.getElementById('status-skipped').textContent = data.filesSkipped;
    document.getElementById('summary-scanned').textContent = data.filesScanned;
    document.getElementById('summary-skipped').textContent = data.filesSkipped;

    const totalFindings = (data.criticalCount || 0) + (data.mediumCount || 0) + (data.normalCount || 0);
    document.getElementById('status-findings').textContent = totalFindings;
    document.getElementById('summary-total-findings').textContent = totalFindings;

    renderPercentages(data.criticalCount, data.mediumCount, data.normalCount);

    document.getElementById('status-started').textContent = formatTimestamp(data.startTime);
    document.getElementById('status-completed').textContent = data.status === 'RUNNING' ? '–' : formatTimestamp(data.endTime);

    if (data.status !== 'RUNNING') {
      const finalMs = data.endTime
          ? new Date(data.endTime).getTime() - new Date(data.startTime).getTime()
          : 0;
      stopElapsedTicker(finalMs);
    }
  } catch (e) {
    console.error('Failed to poll current run', e);
  }
}

function renderPercentages(critical, medium, normal) {
  const total = (critical + medium + normal) || 1;
  document.getElementById('pct-critical').textContent = `${((critical / total) * 100).toFixed(1)}%`;
  document.getElementById('pct-medium').textContent = `${((medium / total) * 100).toFixed(1)}%`;
  document.getElementById('pct-normal').textContent = `${((normal / total) * 100).toFixed(1)}%`;
}

/* ---------- findings: fetch, filter, paginate ---------- */
async function pollFindings() {
  try {
    const res = await fetch('/api/scans/current/findings');
    allFindings = await res.json();
    applyFindingsFilters();
  } catch (e) {
    console.error('Failed to poll findings', e);
  }
}

function applyFindingsFilters() {
  const search = document.getElementById('findings-search').value.trim().toLowerCase();
  const riskFilter = document.getElementById('risk-filter').value;
  const typeFilter = document.getElementById('type-filter').value;

  filteredFindings = allFindings.filter(f => {
    if (riskFilter && f.riskLevel !== riskFilter) return false;
    if (typeFilter && f.dataType !== typeFilter) return false;
    if (search) {
      const haystack = `${f.fileName} ${f.filePath} ${f.maskedValue}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  }).slice().reverse();

  findingsPage = 1;
  renderFindingsPage();
}

function renderFindingsPage() {
  document.getElementById('findings-count').textContent = filteredFindings.length;

  const totalPages = Math.max(1, Math.ceil(filteredFindings.length / FINDINGS_PAGE_SIZE));
  if (findingsPage > totalPages) findingsPage = totalPages;
  const start = (findingsPage - 1) * FINDINGS_PAGE_SIZE;
  const pageItems = filteredFindings.slice(start, start + FINDINGS_PAGE_SIZE);

  const body = document.getElementById('findings-body');
  body.innerHTML = '';

  if (pageItems.length === 0) {
    body.innerHTML = '<tr class="empty-row"><td colspan="8">No findings match your filters</td></tr>';
  } else {
    pageItems.forEach(f => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="mono">${f.fileName}</td>
        <td class="mono">${f.filePath}</td>
        <td>${friendlyType(f.dataType)}</td>
        <td><span class="badge-risk ${f.riskLevel}">${f.riskLevel}</span></td>
        <td class="mono">${f.maskedValue}</td>
        <td>${formatTimestamp(f.scanTimestamp)}</td>
        <td>${formatTimestamp(f.fileCreationTime)}</td>
        <td>${formatTimestamp(f.fileModifiedTime)}</td>`;
      body.appendChild(row);
    });
  }

  renderPagination('findings-pagination', findingsPage, totalPages, filteredFindings.length, FINDINGS_PAGE_SIZE, (p) => {
    findingsPage = p;
    renderFindingsPage();
  });
}

document.getElementById('findings-search').addEventListener('input', applyFindingsFilters);
document.getElementById('risk-filter').addEventListener('change', applyFindingsFilters);
document.getElementById('type-filter').addEventListener('change', applyFindingsFilters);
document.getElementById('clear-filters-btn').addEventListener('click', () => {
  document.getElementById('findings-search').value = '';
  document.getElementById('risk-filter').value = '';
  document.getElementById('type-filter').value = '';
  applyFindingsFilters();
});

/* ---------- scan history: fetch, paginate ---------- */
async function pollHistory() {
  try {
    const res = await fetch('/api/scans/history');
    allHistory = await res.json();
    renderHistoryPage();
  } catch (e) {
    console.error('Failed to poll history', e);
  }
}

function renderHistoryPage() {
  const totalPages = Math.max(1, Math.ceil(allHistory.length / HISTORY_PAGE_SIZE));
  if (historyPage > totalPages) historyPage = totalPages;
  const start = (historyPage - 1) * HISTORY_PAGE_SIZE;
  const pageItems = allHistory.slice(start, start + HISTORY_PAGE_SIZE);

  const body = document.getElementById('history-body');
  body.innerHTML = '';

  if (pageItems.length === 0) {
    body.innerHTML = '<tr class="empty-row"><td colspan="10">No scans yet</td></tr>';
  } else {
    pageItems.forEach(r => {
      const total = (r.criticalCount || 0) + (r.mediumCount || 0) + (r.normalCount || 0);
      let duration = '–';
      if (r.startTime && r.endTime) {
        duration = formatDurationMs(new Date(r.endTime).getTime() - new Date(r.startTime).getTime());
      }
      const downloadCell = r.status === 'COMPLETED'
          ? `<a href="/api/scans/${r.runId}/download">Download</a>`
          : (r.status === 'RUNNING' ? 'In progress…' : '-');

      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="mono">${r.runId.substring(0, 8)}</td>
        <td><span class="badge-status ${r.status}">${r.status}</span></td>
        <td class="mono">${r.scanPath || '-'}</td>
        <td>${formatTimestamp(r.startTime)}</td>
        <td>${duration}</td>
        <td>${r.criticalCount}</td>
        <td>${r.mediumCount}</td>
        <td>${r.normalCount}</td>
        <td>${total}</td>
        <td>${downloadCell}</td>`;
      body.appendChild(row);
    });
  }

  renderPagination('history-pagination', historyPage, totalPages, allHistory.length, HISTORY_PAGE_SIZE, (p) => {
    historyPage = p;
    renderHistoryPage();
  });
}

/* ---------- shared pagination renderer ---------- */
function renderPagination(containerId, page, totalPages, totalItems, pageSize, onChange) {
  const container = document.getElementById(containerId);
  container.innerHTML = '';
  if (totalItems === 0) return;

  const info = document.createElement('span');
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, totalItems);
  info.className = 'page-info';
  info.textContent = `Showing ${start} to ${end} of ${totalItems}`;
  container.appendChild(info);

  const prev = document.createElement('button');
  prev.className = 'page-btn';
  prev.textContent = '‹';
  prev.disabled = page === 1;
  prev.onclick = () => onChange(page - 1);
  container.appendChild(prev);

  const maxButtons = 5;
  let pages = [];
  if (totalPages <= maxButtons) {
    pages = Array.from({ length: totalPages }, (_, i) => i + 1);
  } else {
    pages = [1, 2, '…', totalPages];
    if (page > 2 && page < totalPages - 1) pages = [1, '…', page, '…', totalPages];
  }

  pages.forEach(p => {
    if (p === '…') {
      const span = document.createElement('span');
      span.textContent = '…';
      span.style.padding = '0 4px';
      container.appendChild(span);
      return;
    }
    const btn = document.createElement('button');
    btn.className = 'page-btn' + (p === page ? ' active' : '');
    btn.textContent = p;
    btn.onclick = () => onChange(p);
    container.appendChild(btn);
  });

  const next = document.createElement('button');
  next.className = 'page-btn';
  next.textContent = '›';
  next.disabled = page === totalPages;
  next.onclick = () => onChange(page + 1);
  container.appendChild(next);
}

/* ---------- settings ---------- */
async function loadSettings() {
  try {
    const res = await fetch('/api/scans/config');
    const cfg = await res.json();
    const el = document.getElementById('settings-content');
    el.innerHTML = `
      <div class="summary-row"><span>Target Drives</span><span class="val">${(cfg.targetDrives || []).join(', ')}</span></div>
      <div class="summary-row"><span>Supported Extensions</span><span class="val">${(cfg.supportedExtensions || []).join(', ')}</span></div>
      <div class="summary-row"><span>Excluded Paths</span><span class="val">${(cfg.excludedPaths || []).length} configured</span></div>
      <div class="summary-row"><span>Excluded Folder Names</span><span class="val">${(cfg.excludedFolderNames || []).join(', ')}</span></div>
      <div class="summary-row"><span>Schedule (cron)</span><span class="val">${cfg.scheduleCron || '-'}</span></div>
      <div class="summary-row"><span>Report Format</span><span class="val">${cfg.report ? cfg.report.format : '-'}</span></div>
      <div class="summary-row"><span>Report Output Directory</span><span class="val">${cfg.report ? cfg.report.outputDirectory : '-'}</span></div>
    `;
  } catch (e) {
    console.error('Failed to load settings', e);
  }
}

/* ---------- actions ---------- */
function triggerScan() {
  const pathValue = document.getElementById('scan-path-input').value.trim();
  const payload = {};
  if (pathValue) payload.paths = [pathValue];
  if (selectedPiiTypes.length > 0) payload.dataTypes = selectedPiiTypes;
  const hasBody = Object.keys(payload).length > 0;

  fetch('/api/scans/trigger', {
    method: 'POST',
    headers: hasBody ? { 'Content-Type': 'application/json' } : {},
    body: hasBody ? JSON.stringify(payload) : null
  }).then(async r => {
    const msg = await r.text();
    if (!r.ok) {
      alert(msg);
    } else {
      console.log('Scan started.');
      startElapsedTicker(null);
      pollAll();
    }
  });
}

function pollAll() {
  pollCurrent();
  pollFindings();
  pollHistory();
}

loadDataTypes();
loadSettings();
pollAll();
setInterval(pollAll, 2000);