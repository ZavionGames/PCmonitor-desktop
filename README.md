# PCMonitor Agent

Kişisel Windows bilgisayarında arka planda çalışan PCMonitor agent'ı.  
Uygulama açılış/kapanışlarını ve sistem olaylarını SQLite kuyruğuna yazar, web API'sine gönderir.  
Birden fazla bilgisayarda çalışabilir; her makine yalnızca kendi verisini yazar.

---

## Gereksinimler

- Windows 10/11, 64-bit
- Python 3.12 veya üzeri

---

## Kurulum

```powershell
cd pcmonitor-agent
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

`pywin32` — mutex, konsol sinyali, DPAPI, Windows Olay Günlüğü için gereklidir.  
`httpx` — Firestore REST ve web API istekleri için.  
`psutil` — süreç izleme.  
`pystray` + `Pillow` — sistem tepsisi simgesi (isteğe bağlı; `trayEnabled: false` ile kapatılabilir).

---

## Çalıştırma

```powershell
# Konsoldan (Ctrl+C ile durur)
.\.venv\Scripts\python.exe -m pcmonitor

# Konsolsuz — arka plan modu
.\.venv\Scripts\pythonw.exe -m pcmonitor

# Sürümü göster
.\.venv\Scripts\python.exe -m pcmonitor --version
```

---

## Makine Kimliği ve Etiket

Agent her başladığında `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` değerini okur.  
Bu GUID, Firestore'daki `machines/{machineGuid}` dokümanının adıdır.  
**Her makine yalnızca kendi GUID'iyle eşleşen dokümanı yazar; başka makinelere asla dokunmaz.**

Web panelinde makineleri "PC 1", "PC 2" gibi isimlerle ayırt etmek için etiket kullanılır:

```powershell
# Makine etiketini ayarla ve config.json'a kaydet
.\.venv\Scripts\python.exe -m pcmonitor --set-label "PC 1"

# Ana bilgisayar için
.\.venv\Scripts\python.exe -m pcmonitor --set-label "Ana PC"

# Test makinesi için
.\.venv\Scripts\python.exe -m pcmonitor --set-label "Test PC"
```

Etiket ayarlanmamışsa Firestore'a `computerName` değeri yazılır.

---

## Test Modu

Arka plan servisini başlatmadan yalnızca makine kimliğini okur, Firestore'a giriş kaydı yazar ve çıkar.  
Kurulum doğrulaması için kullanılır.

```powershell
.\.venv\Scripts\python.exe -m pcmonitor --test
```

Örnek çıktı:

```
--- PCMonitor Test Modu ---
Agent sürümü : 0.1.0
MachineGuid  : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Kullanıcı    : kullanici_adi
Bilgisayar   : DESKTOP-ABC123
Etiket       : PC 1
OS           : Windows-11-10.0.22621-SP0
Zaman (UTC)  : 2026-11-13T10:00:00Z
Zaman (yerel): 2026-11-13T13:00:00+03:00

etiket=PC 1 machineGuid=... kullanıcı=... firestore=başarılı
```

Çıkış kodu `0` = başarılı, `1` = Firestore yazma hatası.

---

## Diğer Komut Satırı Bayrakları

```powershell
# Oturum açılınca otomatik başlat (HKCU Run kaydı — yönetici gerekmez)
.\.venv\Scripts\python.exe -m pcmonitor --install-autostart

# Otomatik başlatmayı kaldır
.\.venv\Scripts\python.exe -m pcmonitor --remove-autostart

# Web panelinden eşleştirme kodu alındıktan sonra
.\.venv\Scripts\python.exe -m pcmonitor --pair <KOD>
```

---

## Veri Dosyaları

| Dosya | Yol |
|---|---|
| Yapılandırma | `%LOCALAPPDATA%\PCMonitor\config.json` |
| Veritabanı | `%LOCALAPPDATA%\PCMonitor\pcmonitor.sqlite3` |
| Log | `%LOCALAPPDATA%\PCMonitor\logs\agent.log` |
| Cihaz anahtarı | `%LOCALAPPDATA%\PCMonitor\device.key` (DPAPI ile şifreli) |

Log dosyası 1 MB'ta döner, 5 yedek tutulur, tüm zamanlar UTC.  
`PCMONITOR_DATA_DIR` ortam değişkeni veri klasörünü geçersiz kılar (testlerde kullanılır).

---

## config.json Alanları

| Alan | Açıklama | Varsayılan |
|---|---|---|
| `serverUrl` | Web API adresi | `""` |
| `deviceId` | Eşleştirme sonrası otomatik dolar | `""` |
| `logLevel` | `DEBUG` / `INFO` / `WARNING` / `ERROR` | `INFO` |
| `trayEnabled` | Sistem tepsisi simgesi | `true` |
| `firestoreProjectId` | Firestore proje kimliği | `pcmonitors` |
| `firestoreApiKey` | Firestore web API anahtarı | *(bak. default.json)* |
| `label` | Bu makinenin etiketi (ör. `"PC 1"`) | `""` |

`deviceKey` bu dosyada **saklanmaz**; DPAPI ile `device.key` dosyasında tutulur.

---

## Firestore Veri Yapısı

```
machines/
  {machineGuid}/                     ← PATCH ile güncellenen snapshot
    machineGuid   : string
    computerName  : string
    username      : string
    label         : string           ← "PC 1", "PC 2" vb.
    lastSeenUtc   : string (ISO 8601)

    logins/
      {loginId}/                     ← her başlatmada yeni doküman (POST)
        event         : "agent_started"
        machineGuid   : string
        username      : string
        computerName  : string
        osVersion     : string
        agentVersion  : string
        startedAtUtc  : string (ISO 8601 UTC)
        startedAtLocal: string (yerel saat + offset)
```

> **Not:** Login kayıtlarında `label` alanı **yoktur**; web paneli makine dokümanındaki `label`'a bakmalıdır.

---

## Çevrimdışı Dayanıklılık

İnternet yoksa veya Firestore yazması başarısız olursa kayıt SQLite kuyruğuna alınır.  
Bağlantı geldiğinde arka plan döngüsü otomatik olarak yeniden dener.  
Her giriş kaydı benzersiz UUID ile takip edilir; bağlantı kesilip yeniden bağlanınca aynı kayıt iki kez yazılmaz.

---

## Testler

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Testler `PCMONITOR_DATA_DIR` ile geçici klasör kullanır; `%LOCALAPPDATA%` kirlenmez.

---

## Modül Yapısı

```
src/pcmonitor/
├── __main__.py          # CLI giriş noktası, komut satırı bayrakları
├── app.py               # Thread yönetimi, başlatma/durdurma
├── config.py            # config.json, yollar, Settings dataclass
├── models.py            # Olay tipleri, Event dataclass, zaman yardımcıları
├── db.py                # SQLite şeması, olay kuyruğu, Firestore outbox
├── process_monitor.py   # psutil diff, gruplama, filtre, uzlaştırma
├── system_monitor.py    # Gizli pencere, güç/oturum/kapanış mesajları
├── eventlog_reader.py   # Windows Olay Günlüğü (1074/6005/6006/6008)
├── sync_client.py       # Web API istemcisi, batch, heartbeat, geri çekilme
├── firestore_test_sink.py  # Geçici Firestore REST yazımı (test mekanizması)
├── secrets_store.py     # DPAPI ile cihaz anahtarı
├── autostart.py         # HKCU Run kaydı
├── tray.py              # pystray minimal tepsi menüsü
└── single_instance.py   # Adlandırılmış Windows Mutex
```
