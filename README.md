# Spor Şimdi API Log Analiz Botu

Bu prototip, sahte veya uygulamadan dışa aktarılmış JSONL / Apache-Nginx combined access loglarını okur, deterministik kurallarla inceleyip SQLite veritabanına log ve alarm olarak kaydeder. Bu bir WAF değildir; trafiği engellemez ve harici sistemlerden kendi başına log çekmez.

## Çalıştırma

Windows'ta projeyi test etmek için `run.bat` dosyasına çift tıklayın. Sunucu ayrı bir pencerede açılır; arayüz varsayılan tarayıcıda `http://127.0.0.1:8000/` adresinde yüklenir. Sunucuyu kapatmak için açılan sunucu penceresini kapatın.

Elle çalıştırmak için proje kökünde:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

Arayüz `http://127.0.0.1:8000/`, API dokümantasyonu `http://127.0.0.1:8000/docs` adresindedir. Uygulama başlarken SQLite tablolarını ve `admin`, `analyst`, `viewer` rol kayıtlarını oluşturur. Eski prototip veritabanını da kayıtları silmeden yeni sütunlara yükseltir. Demo logları kendiliğinden içe aktarılmaz; **Demo Logları Yükle** düğmesine basıldığında açıkça yüklenir. Canlı olay akışı sayfa açıldığında veritabanındaki kayıtlarla doldurulur. Gerçek log dosyası izleme de uygulama başlangıcında kapalıdır; **Canlı Dosya Dinleme** sekmesine mutlak dosya yolunu girip **İzlemeyi Başlat** seçilince ilgili dosya her saniye taranır. Başlangıçta dosyanın tamamlanmış mevcut satırları okunur, sonra yeni tamamlanmış satırlar işlenir; **İzlemeyi Durdur** ile izleme sonlandırılır. `.log`, `.jsonl` ve `.txt` dosyaları desteklenir.

Canlı tarama aralığı ve rate-limit eşikleri ortam değişkenleriyle değiştirilebilir:

| Değişken | Varsayılan | Açıklama |
|---|---:|---|
| `LIVE_LOG_POLL_INTERVAL_SECONDS` | `1` | Kullanıcı tarafından başlatılan canlı log dosyası izleme tarama aralığı |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | İstek sayım penceresi |
| `RATE_LIMIT_MAX_REQUESTS` | `20` | Aynı IP için pencere içindeki izin verilen istek sayısı |
| `DATABASE_URL` | Proje klasöründeki `threat_hunter.db` | SQLAlchemy veritabanı bağlantısı |

Bir IP aynı zaman penceresinde eşiği aşarsa aşan istek alarm üretir. HTTP 429, 403, bilinen zararlı payload imzaları ve yaygın SQL/veritabanı hata metinleri de ayrıca tespit edilir. Logların zaman damgaları oran hesabında kullanılır.

## Log biçimleri ve demo

- JSON Lines kayıtları `timestamp`, `source_ip` (veya `ip`), `endpoint` (veya `path`), `http_method` (veya `method`) ve `status_code` (veya `status`) alanlarını taşımalıdır. `payload_data`, `payload` veya `message` isteğe bağlıdır.
- Apache/Nginx combined access log biçimi desteklenir. İstek URL’sinin query kısmı ve user-agent alanı payload analizi için kullanılır.
- `dummy_data/server_access.log` kasıtlı olarak temiz istek, 403, şüpheli POST/SQLi imzası, SQL hata metni ve eşik üstü istek örnekleri içerir. Arayüzdeki demo düğmesiyle yükleyebilir veya **Canlı Dosya Dinleme** sekmesinden izleyebilirsiniz.
- Desteklenmeyen satırlar atlanır; satır numarasıyla API cevabında veya arka plan uygulama loglarında raporlanır.

Uygulama API'si: `POST /api/v1/analyze-log/` tek yapılandırılmış kaydı, `POST /api/v1/ingest-text/` çok satırlı log metnini alır. Kayıt geçmişi ve alarm listesi `GET /api/v1/logs/` ve `GET /api/v1/alerts/` uçlarından görüntülenir.

Sol menüdeki **Raporlama Çıktıları** sekmesi veritabanındaki tüm log ve alarmlardan en çok saldıran IP'leri (alarm üreten benzersiz log sayısına göre) ve alarm türlerinin dağılımını pasta grafikleriyle gösterir. Yüklenen her dosyanın kayıtları; zaman, IP, istek, payload/ham satır ve tespit edilen alarmlarla ayrı ayrı raporlanır. JSON/JSONL/log dosyaları kaynak dosya adıyla veritabanında ilişkilendirilir. **Excel/CSV Olarak İndir** düğmesi özet ve dosya kayıtlarını UTF-8 BOM'lu CSV olarak indirir; dosya Excel'de doğrudan açılabilir. Rapor API'si `GET /api/v1/reports/`, dışa aktarım ise `GET /api/v1/reports/export.csv` adresindedir.

Canlı izleme API'si `GET /api/v1/live-monitor/status/`, `POST /api/v1/live-monitor/start/` (`{"file_path":"C:\\nginx\\logs\\access.log"}`) ve `POST /api/v1/live-monitor/stop/` uçlarını sağlar. İzleyici uygulama kapanırken durdurulur ve sonraki başlatmada otomatik olarak tekrar başlamaz.

Canlı izlemeyi denemek için `dummy_data/live_tail_demo.log` dosyasının mutlak yolunu **Canlı Dosya Dinleme** sekmesine girip izlemeyi başlatın. Dosyaya yeni satır ekleyerek canlı takibi simüle edebilirsiniz:

```powershell
Add-Content -LiteralPath ".\dummy_data\live_tail_demo.log" -Encoding utf8 -Value '198.51.100.24 - - [07/Oct/2026:02:18:30 +0300] "GET /api/auth HTTP/1.1" 429 32 "-" "LiveTail-Demo/1.0"'
```

Test için Canlı Analiz panelindeki **Test Verilerini Sıfırla** düğmesi logları, alarmları ve dosya tarama imleçlerini siler; kullanıcı ve roller korunur. Ardından **Demo Logları Yükle** ile demo kayıtlarını tekrar ekleyebilir veya dosya yükleyebilirsiniz. Aynı işlemin API ucu `POST /api/v1/data/reset/` adresindedir.

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

Testler log ayrıştırmayı, 403/şüpheli POST/SQL hata/rate-limit tespitini, temiz isteğin alarm üretmemesini, rapor agregasyonunu, dosya ayrıntılarını, güvenli test verisi sıfırlamayı ve CSV dışa aktarım güvenliğini kontrol eder.
