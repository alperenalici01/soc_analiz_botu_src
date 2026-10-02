let totalScans = 0;
let totalThreats = 0;

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
}

// -----------------------------------------
// DB GEÇMİŞİ VE İNCELEME MANTIĞI
// -----------------------------------------
async function fetchLogsFromDB() {
    const tbody = document.getElementById('dbTableBody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 30px;">Veriler yükleniyor...</td></tr>';
    
    try {
        const response = await fetch('/api/v1/logs/');
        const logs = await response.json();
        tbody.innerHTML = '';
        
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 30px; color: #94a3b8;">Veritabanında kayıt yok.</td></tr>';
            return;
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
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: #ef4444;">API Bağlantı Hatası!</td></tr>`;
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
                    <td><span class="badge badge-safe">Aktif Koruma</span></td>
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
                    body: JSON.stringify({ content })
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.detail || 'Log dosyası işlenemedi.');
                data.results.forEach(result => renderAnalysisResult(result.log, result));
                if (data.errors.length) {
                    alert(`${data.processed} satır işlendi; ${data.errors.length} hatalı satır var. İlk hata (${data.errors[0].line}. satır): ${data.errors[0].error}`);
                }
            } else {
                const parsedData = JSON.parse(content);
                if (Array.isArray(parsedData)) {
                    for (const log of parsedData) await sendToBackend(log);
                } else {
                    await sendToBackend(parsedData);
                }
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
    } catch (e) { alert("HATA: Kutuya geçerli bir JSON yapıştırın!"); }
}

async function sendToBackend(logObject) {
    try {
        const response = await fetch('/api/v1/analyze-log/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(logObject)
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
        .map(alert => `${escapeHTML(alert.type)} (${escapeHTML(alert.severity)})`)
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

    resultBox.innerHTML = logHTML + resultBox.innerHTML;
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