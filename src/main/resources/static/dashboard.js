let latestRunId = null;
let latestStatus = null;

async function loadDataTypes() {
  try {
    const res = await fetch('/api/scans/data-types');
    const types = await res.json();
    const select = document.getElementById('pii-type-select');
    select.innerHTML = '';
    types.forEach(t => {
      const option = document.createElement('option');
      option.value = t;
      option.textContent = t;
      select.appendChild(option);
    });
  } catch (e) {
    console.error('Failed to load data types', e);
  }
}

async function pollCurrent() {
  try {
    const res = await fetch('/api/scans/current');
    const downloadBtn = document.getElementById('download-btn');

    if (res.status === 204) {
      setBadge('idle', 'IDLE');
      latestStatus = null;
      downloadBtn.disabled = true;
      return;
    }
    const data = await res.json();
    latestRunId = data.runId;
    latestStatus = data.status;

    if (data.status === 'RUNNING') {
      setBadge('running', 'RUNNING');
      document.getElementById('current-file').textContent = data.currentFile ? ('Scanning: ' + data.currentFile) : '';
    } else if (data.status === 'FAILED') {
      setBadge('failed', 'FAILED');
      document.getElementById('current-file').textContent = '';
    } else {
      setBadge('idle', 'IDLE');
      document.getElementById('current-file').textContent = '';
    }

    downloadBtn.disabled = (data.status !== 'COMPLETED');

    document.getElementById('count-critical').textContent = data.criticalCount;
    document.getElementById('count-medium').textContent = data.mediumCount;
    document.getElementById('count-normal').textContent = data.normalCount;
    document.getElementById('count-scanned').textContent = data.filesScanned;
    document.getElementById('count-skipped').textContent = data.filesSkipped;
  } catch (e) {
    console.error('Failed to poll current run', e);
  }
}

function setBadge(cls, text) {
  const badge = document.getElementById('status-badge');
  badge.className = 'badge ' + cls;
  badge.textContent = text;
}

async function pollFindings() {
  try {
    const res = await fetch('/api/scans/current/findings');
    const findings = await res.json();
    const body = document.getElementById('findings-body');
    body.innerHTML = '';
    findings.slice().reverse().forEach(f => {
      const row = document.createElement('tr');
      const created = f.fileCreationTime ? f.fileCreationTime : '-';
      const modified = f.fileModifiedTime ? f.fileModifiedTime : '-';
      row.innerHTML = `<td>${f.fileName}</td><td>${f.filePath}</td><td>${f.dataType}</td>` +
        `<td class="risk-${f.riskLevel}">${f.riskLevel}</td><td>${f.maskedValue}</td>` +
        `<td>${f.scanTimestamp}</td><td>${created}</td><td>${modified}</td>`;
      body.appendChild(row);
    });
  } catch (e) {
    console.error('Failed to poll findings', e);
  }
}

async function pollHistory() {
  try {
    const res = await fetch('/api/scans/history');
    const runs = await res.json();
    const body = document.getElementById('history-body');
    body.innerHTML = '';
    runs.forEach(r => {
      const row = document.createElement('tr');
      const downloadCell = r.status === 'COMPLETED'
        ? `<a href="/api/scans/${r.runId}/download">Download</a>`
        : (r.status === 'RUNNING' ? 'In progress...' : '-');
      row.innerHTML = `<td>${r.runId.substring(0, 8)}</td><td>${r.status}</td><td>${r.startTime}</td>` +
        `<td>${r.criticalCount}</td><td>${r.mediumCount}</td><td>${r.normalCount}</td><td>${downloadCell}</td>`;
      body.appendChild(row);
    });
  } catch (e) {
    console.error('Failed to poll history', e);
  }
}

function triggerScan() {
  const pathValue = document.getElementById('scan-path-input').value.trim();
  const selectedTypes = Array.from(document.getElementById('pii-type-select').selectedOptions)
    .map(opt => opt.value);

  const payload = {};
  if (pathValue) payload.paths = [pathValue];
  if (selectedTypes.length > 0) payload.dataTypes = selectedTypes;

  const hasBody = Object.keys(payload).length > 0;

  fetch('/api/scans/trigger', {
    method: 'POST',
    headers: hasBody ? { 'Content-Type': 'application/json' } : {},
    body: hasBody ? JSON.stringify(payload) : null
  })
    .then(async r => {
      const msg = await r.text();
      if (!r.ok) {
        alert(msg);
      }
      console.log(msg);
    });
}

function downloadLatest() {
  if (latestRunId && latestStatus === 'COMPLETED') {
    window.location.href = '/api/scans/' + latestRunId + '/download';
  }
}

function pollAll() {
  pollCurrent();
  pollFindings();
  pollHistory();
}

loadDataTypes();
pollAll();
setInterval(pollAll, 2000);
