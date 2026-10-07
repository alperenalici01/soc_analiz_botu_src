# SOC Log Analiz Botu

JSON ve Apache/Nginx access loglarını kural tabanlı analiz ederek SQLite veritabanına kaydeden, alarmları ve raporları web arayüzünde gösteren bir SOC prototipidir.

> Bu uygulama bir WAF değildir: trafiği engellemez, dış sistemlerden kendiliğinden log çekmez ve kimlik doğrulama/rol bazlı erişim sağlamaz. Canlı dosya izleme yalnızca kullanıcı başlattığında çalışır.

## Gereksinimler ve başlatma

- Windows için `run.bat` dosyasını çalıştırın. Sunucu penceresi açılır ve arayüz tarayıcıda `http://127.0.0.1:8000/` adresinden yüklenir.
- Elle başlatmak için Python 3.10+ gerekir:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

Arayüz `http://127.0.0.1:8000/`, etkileşimli API dokümantasyonu `http://127.0.0.1:8000/docs` adresindedir.

Uygulama ilk açıldığında veritabanı tabloları oluşturulur ve eksik varsayılan roller eklenir. Mevcut veriler korunur; demo logları otomatik yüklenmez ve dosya izleme otomatik başlamaz.

## Arayüz

- **Canlı Analiz Paneli:** JSON veya metin log dosyası yükleyin, JSON verisini elle yapıştırın ya da demo kayıtlarını ekleyin. Olay akışı veritabanındaki son kayıtlarla açılır.
- **Geçmiş Kayıtlar (DB):** En son log kayıtlarını ve payload ayrıntılarını görüntüleyin.
- **Kural Motoru Ayarları:** Etkin tespit imzalarını görün ve yeni imza ekleyin. Eklenen imzalar yalnızca çalışan sunucu süreci boyunca bellekte tutulur.
- **Raporlama Çıktıları:** Toplam log ve alarm sayılarını, alarm üreten loglara göre en çok saldıran IP'leri ve alarm türlerini pasta grafikleriyle inceleyin. Kaynak dosyası bulunan loglar için dosya adı/yolu, istek alanları, payload veya ham satır ve alarmlar ayrı ayrı gösterilir. **Excel/CSV Olarak İndir** rapor özetini ve dosya kayıtlarını indirir.
- **Canlı Dosya Dinleme:** Sunucunun erişebildiği `.log`, `.jsonl` veya `.txt` dosyalarının mutlak yollarını satır başına bir tane girip izlemeyi elle başlatın/durdurun. Dosyalar ayrı asenkron görevlerde izlenir. İlk kez izlenen dosyanın tamamlanmış satırları okunur; imleç veritabanında saklandığından sonraki başlatmalarda kaldığı yerden devam edilir. Uygulama kapanınca izleme durur ve yeniden açılışta kendiliğinden başlamaz.

Canlı izleme durdurulduğunda **Raporu Görüntüle** düğmesi ilgili rapor sayfasına geçiş sağlar.

## Log biçimleri

### JSON ve JSON Lines

Tek bir JSON nesnesi veya nesne dizisi yüklenebilir. Gerekli alanların alternatif adları:

| Alan | Kabul edilen adlar |
|---|---|
| Zaman | `timestamp` veya `@timestamp` (ISO-8601) |
| Kaynak IP | `source_ip`, `ip` veya `client_ip` |
| İstek hedefi | `endpoint`, `path` veya `url` |
| HTTP metodu | `http_method` veya `method` |
| HTTP durum kodu | `status_code` veya `status` |
| İsteğe bağlı içerik | `payload_data`, `payload` veya `message` |

`.jsonl`, `.log` ve `.txt` dosyaları satır satır JSON veya Apache/Nginx combined access log olarak işlenir. Desteklenmeyen satırlar atlanır; metin içe aktarma API'si hatalı satır numaralarını yanıtında bildirir.

Örnek JSON:

```json
{
  "timestamp": "2026-10-07T02:30:00+03:00",
  "source_ip": "203.0.113.10",
  "endpoint": "/api/login",
  "http_method": "POST",
  "status_code": 403,
  "payload_data": "örnek içerik"
}
```

## Tespitler

Kural motoru HTTP 403 ve 429 yanıtlarını, POST isteklerindeki bilinen zararlı imzaları, yaygın SQL/veritabanı hata metinlerini ve yapılandırılmış zaman penceresinde eşik üstüne çıkan IP isteklerini raporlar. İnceleme deterministiktir; sonuçlar engelleme veya otomatik müdahale anlamına gelmez.

## Demo ve canlı izleme testi

Canlı Analiz Paneli'ndeki **Demo Logları Yükle** düğmesi `dummy_data/server_access.log` dosyasındaki örnekleri işler. Aynı dosya **Canlı Dosya Dinleme** sekmesinde de seçilebilir.

Canlı eklemeyi simüle etmek için:

1. Canlı Dosya Dinleme sekmesinde izlemek istediğiniz dosyaların mutlak yollarını satır başına bir tane girip izlemeyi başlatın. Örnek: `dummy_data/live_tail_demo.log`.
2. Başka bir PowerShell penceresinden dosyaya yeni tamamlanmış satır ekleyin:

```powershell
Add-Content -LiteralPath ".\dummy_data\live_tail_demo.log" -Encoding utf8 -Value '198.51.100.24 - - [07/Oct/2026:02:18:30 +0300] "GET /api/auth HTTP/1.1" 429 32 "-" "LiveTail-Demo/1.0"'
```

3. İşlenen sayaçları kontrol edin, izlemeyi durdurun ve **Raporu Görüntüle** seçeneğiyle sonuçları inceleyin.

## Veriler ve yapılandırma

Varsayılan veritabanı proje klasöründeki `threat_hunter.db` SQLite dosyasıdır. Mevcut kurulumlarda `DATABASE_URL` ile bağlantı adresi değiştirilebilir.

| Ortam değişkeni | Varsayılan | Açıklama |
|---|---:|---|
| `DATABASE_URL` | Proje klasöründeki SQLite veritabanı | SQLAlchemy veritabanı bağlantısı |
| `LIVE_LOG_POLL_INTERVAL_SECONDS` | `1` | Canlı dosyanın tarama aralığı (saniye) |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | IP istek sayımı için zaman penceresi (saniye) |
| `RATE_LIMIT_MAX_REQUESTS` | `20` | Zaman penceresi içindeki istek eşiği |

**Test Verilerini Sıfırla** işlemi logları, alarmları ve dosya izleme imleçlerini siler; kullanıcı ve roller korunur. İzleme imleçleri silindiğinde aynı dosya tekrar başlatılırsa tamamlanmış satırlar baştan işlenebilir. İşlem geri alınamaz.

## API uçları

`/docs` sayfasında istek ve yanıt şemaları görülebilir.

| Metot | Uç | Açıklama |
|---|---|---|
| `POST` | `/api/v1/analyze-log/` | Tek JSON logunu analiz eder ve kaydeder |
| `POST` | `/api/v1/ingest-text/` | JSON Lines veya access log metnini içe aktarır |
| `POST` | `/api/v1/demo/` | Demo log dosyasını işler |
| `GET` | `/api/v1/logs/` | Son log kayıtlarını listeler |
| `GET` | `/api/v1/alerts/` | Alarm kayıtlarını listeler |
| `GET` | `/api/v1/reports/` | Rapor verilerini döndürür |
| `GET` | `/api/v1/reports/export.csv` | Excel uyumlu CSV raporu indirir |
| `POST` | `/api/v1/data/reset/` | Test loglarını, alarmları ve imleçleri siler |
| `GET` | `/api/v1/rules/` | Etkin imza ve SQL hata kurallarını listeler |
| `POST` | `/api/v1/rules/` | Çalışan süreç için imza ekler |
| `GET` | `/api/v1/live-monitor/status/` | Canlı izleme durumunu döndürür |
| `POST` | `/api/v1/live-monitor/start/` | `file_paths` listesiyle (tek dosyada eski `file_path` alanı da desteklenir) izlemeyi başlatır |
| `POST` | `/api/v1/live-monitor/stop/` | Canlı izlemeyi durdurur |

Çoklu dosya başlatma isteği örneği:

```json
{
  "file_paths": [
    "C:\\nginx\\logs\\access.log",
    "C:\\apache\\logs\\access.log"
  ]
}
```

## Testler

```powershell
python -m unittest discover -s tests -v
```

Testler log ayrıştırma ve tespitleri, veritabanı işlemlerini, raporlama/CSV çıktısını ve kullanıcı kontrollü canlı izleme davranışını kapsar.
