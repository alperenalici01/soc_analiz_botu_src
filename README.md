# Spor Şimdi API Log Analiz Botu

Bu prototip, sahte veya uygulamadan dışa aktarılmış JSONL / Apache-Nginx combined access loglarını okur, deterministik kurallarla inceleyip SQLite veritabanına log ve alarm olarak kaydeder. Bu bir WAF değildir; trafiği engellemez ve harici sistemlerden kendi başına log çekmez.

## Çalıştırma

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

Arayüz `http://127.0.0.1:8000/`, API dokümantasyonu `http://127.0.0.1:8000/docs` adresindedir. Uygulama başlarken SQLite tablolarını ve `admin`, `analyst`, `viewer` rol kayıtlarını oluşturur. Log izleyici `logs` klasörünü her 5 saniyede bir tarar; yeni ve tamamlanmış `.log` / `.jsonl` satırlarını bir kez işler. Klasöre dosya yazan log forwarder/RPA işlemi, uygulamaya otomatik dosya tabanlı kaynak sağlayabilir.

İzleme yolu ve tarama/rate-limit eşikleri ortam değişkenleriyle değiştirilebilir:

| Değişken | Varsayılan | Açıklama |
|---|---:|---|
| `LOG_WATCH_DIR` | `logs` | Arka plan izleyicisinin taradığı klasör |
| `LOG_POLL_INTERVAL_SECONDS` | `5` | Tarama aralığı |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | İstek sayım penceresi |
| `RATE_LIMIT_MAX_REQUESTS` | `20` | Aynı IP için pencere içindeki izin verilen istek sayısı |
| `DATABASE_URL` | `sqlite:///./threat_hunter.db` | SQLAlchemy veritabanı bağlantısı |

Bir IP aynı zaman penceresinde eşiği aşarsa aşan istek alarm üretir. HTTP 429, 403, bilinen zararlı payload imzaları ve yaygın SQL/veritabanı hata metinleri de ayrıca tespit edilir. Logların zaman damgaları oran hesabında kullanılır.

## Log biçimleri ve demo

- JSON Lines kayıtları `timestamp`, `source_ip` (veya `ip`), `endpoint` (veya `path`), `http_method` (veya `method`) ve `status_code` (veya `status`) alanlarını taşımalıdır. `payload_data`, `payload` veya `message` isteğe bağlıdır.
- Apache/Nginx combined access log biçimi desteklenir. İstek URL’sinin query kısmı ve user-agent alanı payload analizi için kullanılır.
- `dummy_data/server_access.log` kasıtlı olarak temiz istek, 403, şüpheli POST/SQLi imzası, SQL hata metni ve eşik üstü istek örnekleri içerir. Arayüzden bu dosyayı yükleyebilir veya arka plan taraması için `logs` klasörüne koyabilirsiniz.
- Desteklenmeyen satırlar atlanır; satır numarasıyla API cevabında veya arka plan uygulama loglarında raporlanır.

Uygulama API'si: `POST /api/v1/analyze-log/` tek yapılandırılmış kaydı, `POST /api/v1/ingest-text/` çok satırlı log metnini alır. Kayıt geçmişi ve alarm listesi `GET /api/v1/logs/` ve `GET /api/v1/alerts/` uçlarından görüntülenir.

## Veritabanı modeli

- `api_logs`: kaynak IP, zaman, endpoint, HTTP metodu/durum, payload, ham satır ve kaynak dosya.
- `security_alerts`: tespitler; `log_id` üzerinden `api_logs` tablosuna foreign key.
- `roles` ve `users`: kullanıcı-rol ilişkisi `users.role_id` foreign key'iyle tutulur. Varsayılan roller `admin`, `analyst`, `viewer` olarak eklenir.
- `file_checkpoints`: izlenen her dosyanın son işlenen byte konumu; dosya satırlarıyla aynı transaction içinde güncellenir.

Rol tabloları başlangıç şemasıdır; kimlik doğrulama, parola saklama ve rol bazlı API yetkilendirmesi bu prototipte uygulanmamıştır. İmza ekleme uç noktası da imzayı yalnızca çalışan süreç belleğinde tutar.

## Test

```powershell
python -m unittest discover -s tests -v
```

Testler log ayrıştırmayı, 403/şüpheli POST/SQL hata/rate-limit tespitini ve temiz isteğin alarm üretmemesini kontrol eder.
