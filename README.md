Tamam! Aşağıda, WebGrabber için daha çekici ve anlaşılır bir `README.md` dosyası ve gerekli bağımlılıkları listeleyen `requirements.txt` dosyası bulunuyor. `README.md` dosyasını, emojilerle daha ilgi çekici hale getirdim.

### `README.md` İçeriği

```markdown
# 🌐 WebGrabber

**WebGrabber** - İleri Düzey Web İndirme ve Güvenlik Tarama Aracı 🚀

WebGrabber, web sitelerinden çeşitli dosya türlerini indirip, güvenlik açıklarını tarayarak içerikleri analiz etmek için geliştirilmiş güçlü bir araçtır. Geniş parametre desteği ile yapılandırılabilir ve statik veya dinamik içeriklere yönelik taramalar yapabilir.

## ✨ Özellikler

- 📂 **Geniş Dosya Türü Desteği**: `.html`, `.js`, `.css`, `.php`, `.json`, `.xml`, `.pdf`, `.docx`, `.png`, `.jpg`, `.mp4` ve daha birçok dosya türünü destekler.
- 🔒 **Güvenlik Açığı Kontrolleri**: XSS, SQL Injection, SSRF, ve diğer yaygın güvenlik açıklarına karşı gelişmiş tarama.
- 🍪 **Çerez Yönetimi**: Tüm çerezlerin çekilmesi ve kaydedilmesi, oturum yönetimi.
- ⚡ **Çoklu İndirme Desteği**: Asenkron ve çok iş parçacıklı yapı ile hızlı indirme.
- 🕸️ **Selenium Entegrasyonu**: JavaScript çalıştırma ve dinamik içeriklerin yüklenmesi.
- 📊 **Çıktı Formatları**: Verileri CSV, JSON ve XML formatlarında kaydetme.
- 🔁 **Gelişmiş Hata Yönetimi ve Yeniden Deneme**: Hata durumunda otomatik yeniden deneme mekanizması.

## 🛠️ Gereksinimler

- Python 3.6 veya üzeri sürüm
- Aşağıdaki Python kütüphaneleri:

```bash
pip install -r requirements.txt
```

## 📦 Kurulum

1. Bu projeyi klonlayın veya indirin:

    ```bash
    git clone https://github.com/yourusername/webgrabber.git
    cd webgrabber
    ```

2. Gereksinimleri yükleyin:

    ```bash
    pip install -r requirements.txt
    ```

## 🚀 Kullanım

WebGrabber'ı çalıştırmak için temel komut:

```bash
python webgrabber.py --urls http://example.com --dir indirilen_dosya --output-format json
```

### 🔧 Örnek Kullanım

- Bir web sitesinden belirli dosyaları indirin:

    ```bash
    python webgrabber.py --urls http://example.com --dir indirilen_dosya --depth 2 --download-images
    ```

- Proxy kullanarak indirme yapın:

    ```bash
    python webgrabber.py --urls http://example.com --proxy http://127.0.0.1:8080 --dir indirilen_dosya
    ```

- Çerezleri kaydederek indirme yapın:

    ```bash
    python webgrabber.py --urls http://example.com --cookies "sessionid=abcd1234; csrftoken=xyz9876" --dir indirilen_dosya
    ```

## 📄 Lisans

Bu proje MIT lisansı ile lisanslanmıştır - daha fazla bilgi için `LICENSE` dosyasına bakınız.

## 🤝 Katkıda Bulunun

Katkılarınızı memnuniyetle bekliyoruz! Lütfen katkı rehberimizi okuyun ve `pull request` gönderin. 🎉



