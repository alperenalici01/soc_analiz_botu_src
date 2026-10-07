let totalScans = 0;
let totalThreats = 0;
let latestReport = null;
let liveMonitorTimer = null;
let lastMonitorProcessedCount = null;
const chartColors = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16'];

document.addEventListener('DOMContentLoaded', initializeDashboard);

async function initializeDashboard() {
    await fetchLogsFromDB(true);
    fetchRules();
    fetchLiveMonitorStatus();
}

async function loadDemoLogs() {
    const button = document.querySelector('.panel-header button[onclick="loadDemoLogs()"]');
    if (button) button.disabled = true;
    try {
        const response = await fetch('/api/v1/demo/', { method: 'POST' });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Demo logları yüklenemedi.');
        await fetchLogsFromDB(true);
        await fetchReport();
        alert(`${data.processed} demo logu işlendi, ${data.invalid} satır atlandı. Demo daha önce yüklendiyse yeni kayıt eklenmez.`);
    } catch (error) {
        alert(`Demo logları yüklenemedi: ${error.message}`);
    } finally {
        if (button) button.disabled = false;
    }
}

async function resetTestData() {
    if (!window.confirm('Tüm logları, alarmları ve dosya tarama geçmişini silmek istediğinize emin misiniz? Kullanıcılar ve roller korunur.')) return;
    const button = document.querySelector('button[onclick="resetTestData()"]');
    if (button) button.disabled = true;
    try {
        const response = await fetch('/api/v1/data/reset/', { method: 'POST' });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || `Sıfırlama API HTTP ${response.status}`);
        await fetchLogsFromDB(true);
        await fetchReport();
        alert(`${result.deleted_logs} log, ${result.deleted_alerts} alarm ve ${result.deleted_checkpoints} dosya tarama kaydı silindi. Demo Logları Yükle ile örnek verileri yeniden ekleyebilirsiniz.`);
    } catch (error) {
        alert(`Test verileri sıfırlanamadı: ${error.message}`);
    } finally {
        if (button) button.disabled = false;
    }
}

// GÜVENLİK YAMASI: Ekrana basılan zararlı payloadların tarayıcıda çalışmasını (XSS) engeller
function escapeHTML(str) {
    if (!str) return '';
    return String(str).replace(/[&<>'"]/g, function(tag) {
        const charsToReplace = { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' };
        return charsToReplace[tag] || tag;
    });
}

// SEKME DEĞİŞTİRME MANTIĞI
function switchTab(tabName) {
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    
    const menuEl = document.getElementById('menu-' + tabName);
    if(menuEl) menuEl.classList.add('active');
    
    document.getElementById('view-' + tabName).classList.add('active');

    if (tabName === 'db') fetchLogsFromDB();
    if (tabName === 'rules') fetchRules();
    if (tabName === 'reports') fetchReport();
    if (tabName === 'tail') fetchLiveMonitorStatus();
}

document.getElementById('tail-form').addEventListener('submit', startLiveMonitor);

async function startLiveMonitor(event) {
    event.preventDefault();
    const pathInput = document.getElementById('tail-file-path');
    const startButton = document.getElementById('tail-start');
    const errorBox = document.getElementById('tail-error');
    const filePaths = pathInput.value.split(/\r?\n/).map(path => path.trim()).filter(Boolean);
    errorBox.textContent = '';
    startButton.disabled = true;
    try {
        const response = await fetch('/api/v1/live-monitor/start/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_paths: filePaths })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || `İzleme başlatılamadı (HTTP ${response.status})`);
        pathInput.value = (result.file_paths || filePaths).join('\n');
        document.getElementById('tail-completion').hidden = true;
        renderLiveMonitorStatus(result);
        beginLiveMonitorPolling(result.processed);
    } catch (error) {
        errorBox.textContent = error.message;
    } finally {
        startButton.disabled = false;
    }
}

async function stopLiveMonitor() {
    const errorBox = document.getElementById('tail-error');
    errorBox.textContent = '';
    try {
        const response = await fetch('/api/v1/live-monitor/stop/', { method: 'POST' });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || `İzleme durdurulamadı (HTTP ${response.status})`);
        renderLiveMonitorStatus(result);
        showTailCompletion(result);
        endLiveMonitorPolling();
    } catch (error) {
        errorBox.textContent = error.message;
    }
}

function showTailCompletion(status) {
    const completion = document.getElementById('tail-completion');
    const filePaths = status.file_paths || (status.file_path ? [status.file_path] : []);
    const fileNames = filePaths.map(path => path.split(/[\\/]/).pop());
    const fileLabel = fileNames.length ? fileNames.join(', ') : 'seçilen dosyalar';
    document.getElementById('tail-completion-summary').textContent =
        `${fileLabel}: toplam ${status.processed} satır işlendi, ${status.invalid} hatalı satır atlandı. Rapor ve dosya ayrıntılarını görmek için rapor sayfasına geçin.`;
    completion.hidden = false;
}

function openTailReport() {
    switchTab('reports');
}

async function fetchLiveMonitorStatus() {
    try {
        const response = await fetch('/api/v1/live-monitor/status/');
        const status = await response.json();
        if (!response.ok) throw new Error(status.detail || `İzleme durumu alınamadı (HTTP ${response.status})`);
        renderLiveMonitorStatus(status);
        if (status.active) beginLiveMonitorPolling();
        else {
            endLiveMonitorPolling();
            if (status.state === 'stopped' && (status.file_paths || status.file_path) && status.last_scan) {
                showTailCompletion(status);
            }
        }
    } catch (error) {
        document.getElementById('tail-error').textContent = error.message;
    }
}

function renderLiveMonitorStatus(status) {
    const state = document.getElementById('tail-state');
    const stateLabels = {
        starting: 'Başlatılıyor…',
        running: '🟢 İzleniyor',
        stopped: 'İzleme kapalı',
        error: '🔴 Hata'
    };
    state.textContent = stateLabels[status.state] || 'İzleme kapalı';
    state.classList.toggle('active', Boolean(status.active));
    document.getElementById('tail-start').disabled = Boolean(status.active);
    document.getElementById('tail-stop').disabled = !status.active;
    document.getElementById('tail-processed').textContent = status.processed.toLocaleString('tr-TR');
    document.getElementById('tail-invalid').textContent = status.invalid.toLocaleString('tr-TR');
    document.getElementById('tail-last-scan').textContent = status.last_scan
        ? new Date(status.last_scan).toLocaleString('tr-TR')
        : 'Henüz taranmadı';
    const filePaths = status.file_paths || (status.file_path ? [status.file_path] : []);
    if (filePaths.length) document.getElementById('tail-file-path').value = filePaths.join('\n');
    const fileList = document.getElementById('tail-files');
    fileList.replaceChildren();
    for (const file of status.files || []) {
        const item = document.createElement('li');
        const path = document.createElement('code');
        path.textContent = file.file_path;
        const details = document.createElement('span');
        details.textContent =
            `${file.state}: ${file.processed.toLocaleString('tr-TR')} işlendi, ${file.invalid.toLocaleString('tr-TR')} hatalı`;
        item.append(path, details);
        if (file.error) {
            const error = document.createElement('span');
            error.className = 'tail-file-error';
            error.textContent = file.error;
            item.appendChild(error);
        }
        fileList.appendChild(item);
    }
    if (status.error) document.getElementById('tail-error').textContent = status.error;
}

function beginLiveMonitorPolling(processedCount = null) {
    if (liveMonitorTimer !== null) return;
    lastMonitorProcessedCount = processedCount;
    liveMonitorTimer = window.setInterval(pollLiveMonitor, 1500);
}

function endLiveMonitorPolling() {
    if (liveMonitorTimer !== null) window.clearInterval(liveMonitorTimer);
    liveMonitorTimer = null;
    lastMonitorProcessedCount = null;
}

async function pollLiveMonitor() {
    try {
        const response = await fetch('/api/v1/live-monitor/status/');
        const status = await response.json();
        if (!response.ok) throw new Error(status.detail || `İzleme durumu alınamadı (HTTP ${response.status})`);
        renderLiveMonitorStatus(status);
        if (lastMonitorProcessedCount !== null && status.processed > lastMonitorProcessedCount) {
            await fetchLogsFromDB(true);
            await fetchReport();
        }
        lastMonitorProcessedCount = status.processed;
        if (!status.active) {
            if (status.state === 'stopped' && (status.file_paths || status.file_path) && status.last_scan) {
                showTailCompletion(status);
            }
            endLiveMonitorPolling();
        }
    } catch (error) {
        document.getElementById('tail-error').textContent = error.message;
        endLiveMonitorPolling();
    }
}

async function fetchReport() {
    const message = document.getElementById('report-message');
    message.textContent = 'Rapor verileri yükleniyor...';
    message.classList.remove('error');
    try {
        const response = await fetch('/api/v1/reports/');
        const report = await response.json();
        if (!response.ok) throw new Error(report.detail || `Rapor API HTTP ${response.status}`);
        latestReport = report;
        document.getElementById('report-total-logs').textContent = report.total_logs.toLocaleString('tr-TR');
        document.getElementById('report-threat-logs').textContent = report.threat_logs.toLocaleString('tr-TR');
        document.getElementById('report-total-alerts').textContent = report.total_alerts.toLocaleString('tr-TR');
        renderPieChart(
            'attackers-chart',
            'attackers-legend',
            report.top_attackers,
            'source_ip',
            'Saldırgan IP bulunamadı.'
        );
        renderPieChart(
            'vulnerabilities-chart',
            'vulnerabilities-legend',
            report.vulnerability_types,
            'alert_type',
            'Tespit edilmiş alarm türü bulunamadı.'
        );
        renderImportedFiles(report.imported_files || []);
        message.textContent = '';
    } catch (error) {
        latestReport = null;
        renderImportedFiles([]);
        message.textContent = `Rapor verileri yüklenemedi: ${error.message}`;
        message.classList.add('error');
    }
}

function renderImportedFiles(files) {
    const container = document.getElementById('file-reports');
    const count = document.getElementById('file-report-count');
    container.replaceChildren();
    count.textContent = `${files.length} dosya`;
    if (!files.length) {
        const empty = document.createElement('div');
        empty.className = 'report-empty';
        empty.textContent = 'Henüz dosya yüklenmemiş. Canlı Analiz Paneli üzerinden bir log/JSON dosyası seçin veya demo loglarını yükleyin.';
        container.appendChild(empty);
        return;
    }

    for (const file of files) {
        const fileSection = document.createElement('details');
        fileSection.className = 'file-report';
        const fileSummary = document.createElement('summary');
        fileSummary.textContent = `${file.file_name} — ${file.total_logs} kayıt, ${file.threat_logs} alarm üreten log, ${file.total_alerts} alarm`;
        fileSection.appendChild(fileSummary);

        const sourcePath = document.createElement('p');
        sourcePath.className = 'file-source-path';
        sourcePath.textContent = file.source_file;
        fileSection.appendChild(sourcePath);

        const breakdown = document.createElement('div');
        breakdown.className = 'file-breakdown';
        breakdown.appendChild(createReportBreakdown('Saldırgan IP', file.top_attackers, 'source_ip'));
        breakdown.appendChild(createReportBreakdown('Alarm türleri', file.vulnerability_types, 'alert_type'));
        fileSection.appendChild(breakdown);

        const logTable = document.createElement('div');
        logTable.className = 'file-log-list';
        for (const log of file.logs) {
            const logSection = document.createElement('details');
            logSection.className = 'file-log-entry';
            const logSummary = document.createElement('summary');
            const timestamp = log.timestamp ? new Date(log.timestamp).toLocaleString('tr-TR') : 'Zaman bilinmiyor';
            logSummary.textContent = `${timestamp} | ${log.source_ip || '-'} | ${log.http_method || '-'} ${log.endpoint || '-'} | HTTP ${log.status_code ?? '-'}`;
            logSection.appendChild(logSummary);

            const fields = document.createElement('dl');
            fields.className = 'file-log-fields';
            const values = [
                ['Kaynak IP', log.source_ip || '-'],
                ['Metot', log.http_method || '-'],
                ['Hedef', log.endpoint || '-'],
                ['Durum kodu', log.status_code ?? '-'],
                ['Payload', log.payload_data || '-'],
                ['Ham satır', log.raw_line || '-']
            ];
            for (const [label, value] of values) {
                const row = document.createElement('div');
                const term = document.createElement('dt');
                const description = document.createElement('dd');
                term.textContent = label;
                description.textContent = String(value);
                row.append(term, description);
                fields.appendChild(row);
            }
            logSection.appendChild(fields);

            const alerts = document.createElement('p');
            alerts.className = 'file-log-alerts';
            alerts.textContent = log.alerts.length
                ? `Alarmlar: ${log.alerts.map(alert => `${alert.alert_type} (${alert.severity_level})`).join(', ')}`
                : 'Bu kayıt için alarm üretilmedi.';
            logSection.appendChild(alerts);
            logTable.appendChild(logSection);
        }
        fileSection.appendChild(logTable);
        container.appendChild(fileSection);
    }
}

function createReportBreakdown(title, items, labelKey) {
    const section = document.createElement('section');
    const heading = document.createElement('h4');
    heading.textContent = title;
    section.appendChild(heading);
    const list = document.createElement('ul');
    if (!items.length) {
        const empty = document.createElement('li');
        empty.textContent = 'Veri yok';
        list.appendChild(empty);
    } else {
        for (const item of items) {
            const row = document.createElement('li');
            row.textContent = `${item[labelKey]}: ${item.count}`;
            list.appendChild(row);
        }
    }
    section.appendChild(list);
    return section;
}

function renderPieChart(canvasId, legendId, entries, labelKey, emptyMessage) {
    const canvas = document.getElementById(canvasId);
    const legend = document.getElementById(legendId);
    const context = canvas.getContext('2d');
    const pixelRatio = window.devicePixelRatio || 1;
    const bounds = canvas.getBoundingClientRect();
    const width = Math.max(bounds.width, 240);
    const height = 240;
    canvas.width = width * pixelRatio;
    canvas.height = height * pixelRatio;
    context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    context.clearRect(0, 0, width, height);
    legend.replaceChildren();

    const total = entries.reduce((sum, entry) => sum + entry.count, 0);
    if (!total) {
        const empty = document.createElement('li');
        empty.className = 'chart-empty';
        empty.textContent = emptyMessage;
        legend.appendChild(empty);
        return;
    }

    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 2 - 8;
    let startAngle = -Math.PI / 2;
    entries.forEach((entry, index) => {
        const sliceAngle = entry.count / total * Math.PI * 2;
        const color = chartColors[index % chartColors.length];
        context.beginPath();
        context.moveTo(centerX, centerY);
        context.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        context.closePath();
        context.fillStyle = color;
        context.fill();
        startAngle += sliceAngle;

        const item = document.createElement('li');
        const swatch = document.createElement('span');
        const label = document.createElement('span');
        swatch.className = 'chart-swatch';
        swatch.style.backgroundColor = color;
        label.textContent = `${entry[labelKey]} — ${entry.count.toLocaleString('tr-TR')} (${(entry.count / total * 100).toFixed(1)}%)`;
        item.append(swatch, label);
        legend.appendChild(item);
    });
}

window.addEventListener('resize', () => {
    if (!latestReport || !document.getElementById('view-reports').classList.contains('active')) return;
    renderPieChart('attackers-chart', 'attackers-legend', latestReport.top_attackers, 'source_ip', 'Saldırgan IP bulunamadı.');
    renderPieChart('vulnerabilities-chart', 'vulnerabilities-legend', latestReport.vulnerability_types, 'alert_type', 'Tespit edilmiş alarm türü bulunamadı.');
});

// -----------------------------------------
// DB GEÇMİŞİ VE İNCELEME MANTIĞI
// -----------------------------------------
async function fetchLogsFromDB(showLiveStream = false) {
    const tbody = document.getElementById('dbTableBody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 30px;">Veriler yükleniyor...</td></tr>';
    
    try {
        const response = await fetch('/api/v1/logs/');
        if (!response.ok) throw new Error(`Log API HTTP ${response.status}`);
        const logs = await response.json();
        const statusBadge = document.getElementById('status-badge');
        if (statusBadge) {
            statusBadge.innerText = '🟢 Backend bağlı';
            statusBadge.style.color = 'var(--success)';
        }
        if (tbody) tbody.innerHTML = '';
        
        if (logs.length === 0) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 30px; color: #94a3b8;">Veritabanında kayıt yok.</td></tr>';
            if (showLiveStream) {
                document.getElementById('resultBox').innerHTML =
                    '<div style="color: var(--text-muted); text-align: center; margin-top: 80px;">Henüz log yok. Demo Logları Yükle düğmesini kullanın.</div>';
                totalScans = 0;
                totalThreats = 0;
                updateCounters();
            }
            return;
        }

        if (showLiveStream) {
            document.getElementById('resultBox').innerHTML = '';
            totalScans = 0;
            totalThreats = 0;
            [...logs].reverse().forEach(log => renderAnalysisResult(log, {
                status: log.alerts && log.alerts.length ? 'danger' : 'safe',
                alerts: (log.alerts || []).map(alert => ({
                    type: alert.alert_type,
                    severity: alert.severity_level
                }))
            }));
        }

        logs.forEach(log => {
            const dateObj = new Date(log.timestamp);
            const formattedDate = dateObj.toLocaleString('tr-TR');
            const isThreat = log.alerts && log.alerts.length > 0;
            const statusColor = isThreat ? 'color: #ef4444;' : 'color: #10b981;';
            const statusText = isThreat ? 'Alarm' : 'Temiz';
            const displayIp = escapeHTML(log.source_ip);
            const displayMethod = escapeHTML(log.http_method);
            const displayEndpoint = escapeHTML(log.endpoint);
            
            const logId = 'db_log_' + log.log_id;
            
            // GÜVENLİK YAMASI: Veritabanından gelen payloadu ekrana basmadan önce temizle
            const displayPayload = log.payload_data ? escapeHTML(log.payload_data) : 'Trafikte ek veri (payload) taşınmamış.';

            const row = `
                <tr>
                    <td>${formattedDate}</td>
                    <td style="font-family: monospace; color: #a5b4fc;">${displayIp}</td>
                    <td><span style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; margin-right: 8px;">${displayMethod}</span> ${displayEndpoint}</td>
                    <td style="font-weight: bold;">${log.status_code}</td>
                    <td class="status-cell" style="${statusColor}">
                        ${statusText}
                        <button class="btn-outline btn-small" style="margin-left: 10px; padding: 2px 8px; font-size: 0.7rem;" onclick="toggleDetails('${logId}')">🔍 İncele</button>
                    </td>
                </tr>
                <tr>
                    <td colspan="5" style="padding: 0; border: none;">
                        <div class="raw-data-box" id="${logId}" style="margin: 0 15px 15px 15px; border-left: 3px solid ${isThreat ? '#ef4444' : '#10b981'};">
                            <strong>Gönderilen Paket (Payload):</strong><br><br>${displayPayload}
                        </div>
                    </td>
                </tr>
            `;
            tbody.innerHTML += row;
        });
    } catch (error) {
        const statusBadge = document.getElementById('status-badge');
        if (statusBadge) {
            statusBadge.innerText = '🔴 Backend erişilemiyor';
            statusBadge.style.color = 'var(--danger)';
        }
        if (tbody) tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: #ef4444;">API Bağlantı Hatası: ${escapeHTML(error.message)}</td></tr>`;
        if (showLiveStream) {
            document.getElementById('resultBox').innerHTML =
                `<div style="color:#ef4444;text-align:center;padding:24px;">Backend'e bağlanılamadı: ${escapeHTML(error.message)}. Uygulamayı README'deki komutla başlatın.</div>`;
        }
    }
}

// -----------------------------------------
// KURAL MOTORU YÖNETİMİ
// -----------------------------------------
async function fetchRules() {
    const tbody = document.getElementById('rulesTableBody');
    try {
        const response = await fetch('/api/v1/rules/');
        const data = await response.json();
        tbody.innerHTML = '';
        
        data.signatures.forEach((sig, index) => {
            // GÜVENLİK YAMASI: Kural motorundaki "<img src=" gibi değerleri güvenli metne çevir (XSS Fix)
            const safeSig = escapeHTML(sig);
            
            const row = `
                <tr>
                    <td style="color: #94a3b8; width: 50px;">${index + 1}</td>
                    <td style="font-family: monospace; color: #f8fafc; font-size: 14px;">${safeSig}</td>
                    <td><span class="badge badge-safe">Tespit kuralı aktif</span></td>
                </tr>
            `;
            tbody.innerHTML += row;
        });
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="3" style="text-align:center; color: #ef4444;">Kural motoruna bağlanılamadı.</td></tr>`;
    }
}

async function addNewSignature() {
    const inputEl = document.getElementById('newSignatureInput');
    const newSig = inputEl.value.trim();
    if (!newSig) { alert("Lütfen boş imza eklemeyin!"); return; }

    try {
        const response = await fetch('/api/v1/rules/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ signature: newSig })
        });
        const result = await response.json();
        
        inputEl.value = ''; 
        fetchRules(); 
        
        if(result.status === 'success') {
            alert("✅ Yeni tespit imzası bu sunucu oturumu boyunca etkin.");
        } else {
            alert("ℹ️ " + result.message);
        }
    } catch (error) {
        alert("Kural eklenirken bir hata oluştu!");
    }
}

// -----------------------------------------
// DOSYA YÜKLEME VE POST İŞLEMLERİ
// -----------------------------------------
document.getElementById('fileInput').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async function(event) {
        try {
            const content = String(event.target.result || '');
            if (/\.(log|txt|jsonl)$/i.test(file.name)) {
                const response = await fetch('/api/v1/ingest-text/', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content, source_file: file.name })
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.detail || 'Log dosyası işlenemedi.');
                data.results.forEach(result => renderAnalysisResult(result.log, result));
                await fetchReport();
                if (data.errors.length) {
                    alert(`${data.processed} satır işlendi; ${data.errors.length} hatalı satır var. İlk hata (${data.errors[0].line}. satır): ${data.errors[0].error}`);
                }
            } else {
                const parsedData = JSON.parse(content);
                if (Array.isArray(parsedData)) {
                    for (const log of parsedData) await sendToBackend(log, file.name);
                } else {
                    await sendToBackend(parsedData, file.name);
                }
                await fetchReport();
            }
        } catch (error) {
            alert(`Dosya analiz edilemedi: ${error.message}`);
        } finally {
            document.getElementById('fileInput').value = '';
        }
    };
    reader.readAsText(file);
});

async function analyzeManualData() {
    const logDataStr = document.getElementById('logInput').value;
    if (!logDataStr) return;
    try {
        const parsedLog = JSON.parse(logDataStr);
        if (Array.isArray(parsedLog)) {
            for (const log of parsedLog) await sendToBackend(log);
        } else {
            await sendToBackend(parsedLog);
        }
        await fetchReport();
    } catch (e) { alert("HATA: Kutuya geçerli bir JSON yapıştırın!"); }
}

async function sendToBackend(logObject, sourceFile = null) {
    const requestData = sourceFile ? { ...logObject, source_file: sourceFile } : logObject;
    try {
        const response = await fetch('/api/v1/analyze-log/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestData)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Log API tarafından kabul edilmedi.');
        renderAnalysisResult(logObject, data);
    } catch (error) {
        alert(`Log gönderilemedi: ${error.message}`);
    }
}

function renderAnalysisResult(logObject, data) {
    const resultBox = document.getElementById('resultBox');
    const emptyState = document.getElementById('empty-state');
    if (emptyState) emptyState.remove();

    totalScans++;
    const timeNow = new Date().toLocaleTimeString('tr-TR');
    const logId = 'log_' + Date.now() + Math.floor(Math.random() * 1000);
    const rawJsonString = escapeHTML(JSON.stringify(logObject, null, 2));
    const sourceIp = escapeHTML(logObject.source_ip || '-');
    const endpoint = escapeHTML(logObject.endpoint || '-');
    const threats = (data.alerts || (data.alert_details ? [data.alert_details] : []))
        .map(alert => `${escapeHTML(alert.type || alert.alert_type)} (${escapeHTML(alert.severity || alert.severity_level)})`)
        .join('<br>');

    let logHTML = '';
    if (data.status === 'danger') {
        totalThreats++;
        logHTML = `
            <div class="log-item danger">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <strong style="color: #f8fafc;">🚨 Tehdit tespit edildi</strong>
                    <span class="badge badge-danger">ALARM</span>
                </div>
                <div style="color: #ef4444; font-size: 0.85rem; margin-bottom: 10px;">${threats}</div>
                <div style="color: #94a3b8; font-size: 0.8rem; margin-bottom: 10px;">IP: ${sourceIp} | Hedef: ${endpoint} | ${timeNow}</div>
                <button class="btn-outline btn-small" onclick="toggleDetails('${logId}')">🔍 Paketi İncele</button>
                <div class="raw-data-box" id="${logId}">${rawJsonString}</div>
            </div>`;
    } else {
        logHTML = `
            <div class="log-item safe">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <strong style="color: #f8fafc;">✅ Temiz Trafik</strong>
                    <span class="badge badge-safe">GÜVENLİ</span>
                </div>
                <div style="color: #94a3b8; font-size: 0.8rem; margin-bottom: 10px;">IP: ${sourceIp} | Hedef: ${endpoint} | ${timeNow}</div>
                <button class="btn-outline btn-small" onclick="toggleDetails('${logId}')">🔍 Paketi İncele</button>
                <div class="raw-data-box" id="${logId}">${rawJsonString}</div>
            </div>`;
    }

    resultBox.insertAdjacentHTML('afterbegin', logHTML);
    updateCounters();
}

function updateCounters() {
    document.getElementById('count-total').innerText = totalScans;
    document.getElementById('count-threats').innerText = totalThreats;
}

function clearStream() {
    document.getElementById('resultBox').innerHTML = `<div style="color: #94a3b8; text-align: center; margin-top: 80px; font-style: italic;" id="empty-state">Ekran temizlendi. Yeni loglar bekleniyor...</div>`;
}

function toggleDetails(id) {
    const box = document.getElementById(id);
    box.style.display = box.style.display === "block" ? "none" : "block";
}