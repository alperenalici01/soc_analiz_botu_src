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
            const isThreat = log.status_code >= 400 || (log.payload_data && log.payload_data.includes('script')); 
            const statusColor = isThreat ? 'color: #ef4444;' : 'color: #10b981;';
            const statusText = isThreat ? 'Bloke' : 'Temiz';
            
            const logId = 'db_log_' + log.log_id;
            
            // GÜVENLİK YAMASI: Veritabanından gelen payloadu ekrana basmadan önce temizle
            const displayPayload = log.payload_data ? escapeHTML(log.payload_data) : 'Trafikte ek veri (payload) taşınmamış.';

            const row = `
                <tr>
                    <td>${formattedDate}</td>
                    <td style="font-family: monospace; color: #a5b4fc;">${log.source_ip}</td>
                    <td><span style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; margin-right: 8px;">${log.http_method}</span> ${log.endpoint}</td>
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
            alert("✅ Yeni koruma kuralı başarıyla eklendi! Bot artık bu imzayı anında bloklayacak.");
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
            const parsedData = JSON.parse(event.target.result);
            if (Array.isArray(parsedData)) {
                for (const log of parsedData) await sendToBackend(log);
            } else {
                await sendToBackend(parsedData);
            }
            document.getElementById('fileInput').value = ''; 
        } catch (error) {
            alert("Geçersiz JSON formatı!");
        }
    };
    reader.readAsText(file);
});

async function analyzeManualData() {
    const logDataStr = document.getElementById('logInput').value;
    if (!logDataStr) return;
    try {
        const parsedLog = JSON.parse(logDataStr);
        await sendToBackend(parsedLog);
    } catch (e) { alert("HATA: Kutuya geçerli bir JSON yapıştırın!"); }
}

async function sendToBackend(logObject) {
    const resultBox = document.getElementById('resultBox');
    const emptyState = document.getElementById('empty-state');
    if (emptyState) emptyState.remove();

    try {
        const response = await fetch('/api/v1/analyze-log/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(logObject)
        });
        const data = await response.json();
        totalScans++;
        
        const timeNow = new Date().toLocaleTimeString('tr-TR');
        const logId = 'log_' + Date.now() + Math.floor(Math.random() * 1000);
        
        // GÜVENLİK YAMASI: Sağ taraftaki akışa JSON basılırken özel karakterleri escape et
        const rawJsonString = escapeHTML(JSON.stringify(logObject, null, 2));
        
        let logHTML = '';
        if (data.status === 'danger') {
            totalThreats++;
            logHTML = `
            <div class="log-item danger">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <strong style="color: #f8fafc;">🚨 Tehdit: ${escapeHTML(data.alert_details.type)}</strong>
                    <span class="badge badge-danger">${data.alert_details.severity.toUpperCase()}</span>
                </div>
                <div style="color: #94a3b8; font-size: 0.8rem; margin-bottom: 10px;">IP: ${logObject.source_ip || '-'} | Hedef: ${logObject.endpoint || '-'} | ${timeNow}</div>
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
                <div style="color: #94a3b8; font-size: 0.8rem; margin-bottom: 10px;">IP: ${logObject.source_ip || '-'} | Hedef: ${logObject.endpoint || '-'} | ${timeNow}</div>
                <button class="btn-outline btn-small" onclick="toggleDetails('${logId}')">🔍 Paketi İncele</button>
                <div class="raw-data-box" id="${logId}">${rawJsonString}</div>
            </div>`;
        }
        
        resultBox.innerHTML = logHTML + resultBox.innerHTML;
        document.getElementById('count-total').innerText = totalScans;
        document.getElementById('count-threats').innerText = totalThreats;
        
    } catch (error) { console.error("Backend hatası:", error); }
}

function clearStream() {
    document.getElementById('resultBox').innerHTML = `<div style="color: #94a3b8; text-align: center; margin-top: 80px; font-style: italic;" id="empty-state">Ekran temizlendi. Yeni loglar bekleniyor...</div>`;
}

function toggleDetails(id) {
    const box = document.getElementById(id);
    box.style.display = box.style.display === "block" ? "none" : "block";
}