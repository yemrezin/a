# 🛡️ 1. Unrestricted File Upload (Kısıtlamasız Dosya Yükleme Açığı)

Web uygulamalarının kullanıcıdan profil resmi, fatura, PDF veya doküman kabul ettiği yükleme (*upload*) alanlarında, gelen dosyaların uzantı, içerik ve tip kontrollerinin sunucu tarafında eksik veya hatalı yapılması sonucu ortaya çıkan yüksek riskli bir zafiyettir.

> 💣 **Web Shell ve RCE Tehlikesi:** Saldırganlar bu zayıflığı kullanarak sunucu işletim sistemi üzerinde doğrudan komut çalışmalarını (RCE) sağlayacak zararlı script dosyalarını (**Web Shell**) sisteme yüklerler. 

Eğer yüklenen dosyanın kaydedildiği dizinde script çalıştırma (*execution*) yetkisi varsa ve bu dizine dış dünyadan doğrudan tarayıcı üzerinden erişilebiliyorsa, saldırgan sunucu üzerinde tam hakimiyet elde edebilir.

---

## 🔍 Unrestricted File Upload Zafiyetlerinin Teknik Anatomisi

Saldırganlar, basit arayüz kısıtlamalarını ve güvensiz kontrol mekanizmalarını aşmak için şu yöntemleri kullanırlar:

*   🖥️ **İstemci Tarafındaki (Client-side) Kontrolleri Bypass Etmek:** Sadece HTML veya JavaScript ile yapılan dosya uzantısı doğrulamaları saniyeler içinde aşılabilir. Saldırgan tarayıcıdaki JS kodunu devre dışı bırakabilir ya da isteği araya alıp (*Burp Suite vb.*) dosya uzantısını sunucuya gitmeden önce değiştirebilir.
*   📨 **MIME-Type Manipülasyonu:** Sunucu tarafındaki kod, dosyanın tipini yalnızca HTTP istek başlığındaki `Content-Type` parametresine (*örneğin image/png*) bakarak doğruluyorsa; saldırgan bir PHP dosyasının istek başlığını bu değerle manipüle ederek korumayı kolayca aşabilir.
*   🔀 **Çift Uzantı ve Karakter Manipülasyonları:** Sunucuların filtrelerini karıştırmak için `.png.php`, `.php5`, `.phtml` gibi alternatif uzantılar veya işletim sistemlerinin dosya ismi kurallarını suistimal eden `.php.` ya da null byte (`%00`) enjeksiyonları kullanılır.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP örneğinde, kullanıcıların profil resmi yüklemesini sağlayan bir yapı yer almaktadır. Yazılımcı, istemciden gelen dosya ismine ve uzantısına tamamen güvenmekte ve dosyayı doğrudan web kök dizini altında dışa açık bir klasöre kaydetmektedir:

```php
<?php
// GÜVENSİZ YAPI: Hiçbir uzantı, MIME veya içerik kontrolü yapılmıyor!
if (isset($_FILES['avatar'])) {
    $targetDir = "uploads/avatars/";
    
    // Kullanıcının gönderdiği orijinal dosya ismi doğrudan alınıyor
    $targetFile = $targetDir . basename($_FILES['avatar']['name']);
    
    // Dosya hedef klasöre taşınıyor
    if (move_uploaded_file($_FILES['avatar']['tmp_name'], $targetFile)) {
        echo "Profil resminiz başarıyla yüklendi: " . $targetFile;
    } else {
        echo "Dosya yüklenirken bir hata oluştu.";
    }
}
?>
```
🎯 Saldırı Senaryosu
Saldırgan, profil resmi yerine shell.php adında ve içerisinde <?php system($_GET['cmd']); ?> komutu barındıran küçük bir PHP script'i hazırlar ve sisteme yükler.

Sunucu kontrol yapmadığı için dosyayı /uploads/avatars/shell.php olarak kaydeder.

Saldırgan tarayıcısından http://example.com/uploads/avatars/shell.php?cmd=cat /etc/passwd adresini çağırır.

Sonuç: Sunucu tarafında PHP yorumlayıcısı tetiklenir, işletim sistemi komutu çalışır ve hassas sistem verileri saldırgana sızdırılır.

🔐 Doğru ve Güvenli Kod (Secure Code)
Güvenli bir dosya yükleme mimarisi kurmak için istemciden gelen hiçbir veriye (isim, uzantı, MIME tipi) güvenilmemelidir.

Dosya içeriği sunucu tarafında imza (magic numbers) analiziyle doğrulanmalı, dosya ismi tahmin edilemeyecek bir UUID veya kriptografik rastgele bir değerle değiştirilmeli ve dosya kesinlikle çalıştırılma yetkisi olmayan izole bir dizinde saklanmalıdır.
```php
PHP
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {
    $file = $_FILES['avatar'];
    
    // 1. Dosya Boyutu Sınırlandırması (Örn: Maksimum 2 MB)
    $maxFileSize = 2 * 1024 * 1024;
    if ($file['size'] > $maxFileSize) {
        die("Dosya boyutu çok büyük.");
    }
    
    // 2. GÜVENLİ MIME TİPİ VE İÇERİK KONTROLÜ (Magic Numbers / File Signatures)
    // Sadece tarayıcının gönderdiği HTTP başlığına bakılmıyor; dosyanın ilk byte'ları (imzası) taranıyor
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($file['tmp_name']);
    
    $allowedMimeTypes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif'
    ];
    
    if (!array_key_exists($mimeType, $allowedMimeTypes)) {
        die("Geçersiz dosya formatı. Sadece JPEG, PNG ve GIF yükleyebilirsiniz.");
    }
    
    // 3. GÜVENLİ İSİMLENDİRME (UUID / Rastgele İsim)
    // Saldırganın yüklediği dosyanın adındaki özel karakterler ve çift uzantılar bu şekilde tamamen ezilir
    $extension = $allowedMimeTypes[$mimeType];
    $secureName = bin2hex(random_bytes(16)) . '.' . $extension; // Kriptografik rastgele isim
    
    // 4. İZOLE VE ÇALIŞTIRILAMAZ DEPOLAMA ALANI
    // Yüklenen dosyalar web kök dizininin (public_html) dışında bir klasörde saklanmalıdır.
    // Eğer aynı sunucuda tutulması zorunluysa, bu dizinde script çalıştırma yetkileri kapatılmalıdır.
    $uploadDir = "/var/www/secure_uploads/avatars/";
    $targetPath = $uploadDir . $secureName;
    
    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        echo "Dosya güvenli bir şekilde yüklendi.";
    } else {
        echo "Sistem hatası.";
    }
}
?>
```
🧱 Savunma Katmanları (Defense-in-Depth)
Dosya yükleme işlemlerindeki riskleri sıfıra indirmek adına şu derinlemesine savunma katmanları mimariye entegre edilmelidir:

1. Dosya İsimlerini Rastgeleleştirmek (UUID)
Saldırganın yüklediği zararlı bir dosyayı sunucuda tetikleyebilmesi için dosyanın tam yolunu ve adını bilmesi gerekir.

❌ Orijinal İsimleri Çöpe Atın: Yüklenen dosyaların orijinal isimleri tamamen göz ardı edilmelidir.

🔑 Rastgele Tanımlayıcılar: Her dosyaya sunucu tarafında kriptografik olarak güvenli, benzersiz bir tanımlayıcı (UUID v4 veya random_bytes) atanarak yeni bir isim verilmelidir.

📁 Veritabanı Eşleşmesi: Dosyanın orijinal ismi ile bu rastgele üretilen isim arasındaki eşleşme sadece veri tabanında saklanmalıdır. Bu sayede saldırgan, yüklediği dosyanın adını tahmin edip doğrudan erişim sağlayamaz.

2. MIME Tipi ve Dosya İçeriği Doğrulaması (Magic Numbers)
Tarayıcıların veya proxy araçlarının gönderdiği Content-Type başlığı tamamen manipüle edilebilir bir veridir.

🔍 Sihirli Sayılar (Magic Numbers): Dosya doğrulaması yapılırken, dosyanın ham içeriğinin ilk birkaç byte'ında yer alan ve dosya türünü belirten Sihirli Sayılar (Magic Numbers / File Signatures) analiz edilmelidir. Örneğin, bir PNG dosyasının meşru olabilmesi için her zaman 89 50 4E 47 byte dizisiyle başlaması şarttır.

🛠️ Doğrulama Kütüphaneleri: Bu analizi yapan yerleşik kütüphaneler (PHP'de finfo, Node.js'de file-type vb.) kullanılarak sahte uzantılı scriptlerin sisteme sızması engellenmelidir.

3. Dosyaları Yeniden İşlemek ve Boyutlandırmak (Image Re-processing)
Görsel dosyalarının (JPEG, PNG) içerisine gizlenmiş olan zararlı PHP/JS kod bloklarını (Metadata veya EXIF verilerine gizlenen Web Shell kodlarını) temizlemenin en etkili yöntemidir.

🎨 Görsel İşleme: Yüklenen görseller sunucuya kaydedilmeden önce bir görsel işleme kütüphanesi (GD, ImageMagick, Sharp vb.) vasıtasıyla yeniden boyutlandırılmalı (resize), sıkıştırılmalı veya formatı değiştirilmelidir (örneğin PNG'den WebP'ye dönüştürme).

🧹 Kod Temizliği: Görsel sıfırdan yeniden oluşturulacağı için, dosya içerisine veya EXIF meta verilerine sızdırılmış olan tüm zararlı script parçaları ve yabancı kod blokları fiziksel olarak yok edilir.




# 🛡️ 2. ReDoS (Regular Expression Denial of Service)

Saldırganın, bir web uygulamasının girdi doğrulama veya metin işleme süreçlerinde kullanılan Düzenli İfadelerin (*Regular Expressions / Regex*) çalışma mantığındaki ve arama algoritmalarındaki zayıflıkları suistimal ederek, sunucu işlemcisini (CPU) %100 yük altında kilitleyip uygulamayı tamamen yanıtsız ve servis dışı (DoS) bırakmasını sağlayan yıkıcı bir algoritma zafiyetine **ReDoS** denir.

> ⚙️ **Geriye Doğru Takip (Backtracking) Tuzağı:** Bu zafiyet, geleneksel regex motorlarının çoğunda kullanılan **NFA** (*Non-deterministic Finite Automaton / Kararsız Sonlu Otomat*) arama algoritmalarından ve Geriye Doğru Takip (*Backtracking*) mekanizmasından beslenir. 

Eğer tasarlanan regex kalıbı (*pattern*) belirsiz ve iç içe geçmiş tekrarlı gruplar barındırıyorsa ve sisteme gönderilen girdi bu kalıpla neredeyse eşleşip sadece en son karakterde eşleşmeyi bozuyorsa, regex motoru tüm olası eşleşme kombinasyonlarını tek tek denemek zorunda kalır. Girdi uzunluğu arttıkça denenecek kombinasyon sayısı doğrusal değil, üstel (*exponential*) veya yüksek dereceli polinomsal olarak artar ($O(2^n)$ veya $O(n^2)$). Sonuç olarak, çok kısa bir metin bile sunucu işlemcisini dakikalarca kilitleyerek tüm platformun çökmesine yol açabilir.

---

## 🔍 ReDoS Zafiyetlerinin Teknik Anatomisi: Kötü Amaçlı Geriye Doğru Takip (Catastrophic Backtracking)

ReDoS zafiyetinin kalbinde yer alan mekanizmayı anlamak için basit bir örnek üzerinden gidelim. Aşağıdaki regex kalıbını ele alalım:

$$\text{Pattern: } (a+)+b$$

Bu kalıp; bir veya daha fazla "a" harfi grubunun ardışık tekrarlarını ve ardından gelen bir "b" harfini arar.

*   ✅ **Meşru ve Uyumlu Girdi (`aaaaab`):** Regex motoru girdiyi hızla tarar, tüm "a" harflerini gruplarla eşleştirir, sonunda "b" harfini bulur ve doğrulamayı milisaniyeler içinde başarıyla tamamlar.
*   ❌ **Zararlı ve Uyumsuz Girdi (`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX`):** Girdi "X" karakteriyle bittiği için kalıpla eşleşmez. Ancak NFA motoru, kestirip atmak yerine "X" karakterinden önceki "a" serisinin gruplara nasıl dağıtılabileceğine dair tüm matematiksel olasılıkları denemeye başlar.
    *   32 adet "a" harfi için motor; $(a)^{32}$, $(a+)^{32}$, $((a+)+)^{32}$ gibi iç içe geçmiş tekrarları milyarlarca farklı kombinasyonla bölerek eşleştirmeye çalışır.
    *   Her bir başarısız denemede bir adım geri giderek (*backtracking*) alternatif yolları yürütür.
    *   **Sonuç:** Bu durum, işlemci üzerinde milyarlarca gereksiz döngü yaratarak tek bir HTTP isteğinin işlemci çekirdeğini tamamen sömürmesine neden olur.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code - JavaScript / Node.js)
JavaScript ve Node.js'in yerleşik regex motoru (*V8 engine*), backtracking tabanlı bir NFA algoritması kullanır. Aşağıdaki örnekte, kullanıcı e-postalarını doğrulayan ancak iç içe tekrarlı gruplar barındıran güvensiz bir regex tasarımı yer almaktadır:

```javascript
const express = require('express');
const app = express();
app.use(express.json());

// GÜVENSİZ YAPI: İç içe geçmiş esnek ve tekrarlı gruplar barındıran güvensiz bir regex kalıbı.
// ([a-zA-Z0-9.-]+)+ kısmı, tekrarlanan karakterlerin kendi içinde de alt gruplara bölünmesine izin verir.
const EMAIL_REGEX = /^([a-zA-Z0-9.-]+)+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
 
app.post('/api/register', (req, res) => {
    const { email } = req.body;
 
    if (!email) {
        return res.status(400).json({ error: "E-posta adresi zorunludur." });
    }
 
    console.time("regex_duration");
    
    // GÜVENSİZ: Girdi boyutu ve yapısı sınırlandırılmadan doğrudan regex testine tabi tutuluyor
    const isValid = EMAIL_REGEX.test(email);
    
    console.timeEnd("regex_duration");
 
    if (!isValid) {
        return res.status(400).json({ error: "Geçersiz e-posta formatı." });
    }
 
    return res.status(200).json({ message: "Kayıt başarılı." });
});
 
app.listen(3000);
```
🎯 Saldırı SenaryosuSaldırgan, sisteme meşru bir e-posta adresi yerine, eşleşmeyi en sonda bozan ve backtracking tetikleyen şu girdiyi gönderir:JSON{
  "email": "aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa!"
}
Girdinin uzunluğu yalnızca ~100 karakterdir. Ancak bu istek sunucuya ulaştığında, regex motoru üstel karmaşıklık tuzağına düşer.Sonuç: Sunucu işlemcisi (CPU) %100 kullanım oranına fırlar. Tek bir istek Node.js'in tek iş parçacıklı (single-threaded) yapısını tamamen bloke ettiği için, sistem diğer hiçbir masum kullanıcının isteğine yanıt veremez hale gelir ve tamamen kilitlenir.🔐 Doğru ve Güvenli Kod (Secure Code)ReDoS saldırılarını önlemek için regex kalıpları iç içe geçmiş tekrarlı yapılardan arındırılmalı, doğrulanacak girdilerin maksimum uzunlukları (maximum length) regex işleminden önce katı bir şekilde kısıtlanmalı ve mümkünse backtracking yapmayan doğrusal zamanlı ($O(n)$) modern regex kütüphaneleri veya zaman aşımı (timeout) mekanizmaları kullanılmalıdır.

```javascript
const express = require('express');
const safeRegex = require('safe-regex'); // Kalıp güvenliğini denetleyen kütüphane
const app = express();
app.use(express.json());

// GÜVENLİ YAPI: İç içe tekrarlardan arındırılmış, doğrusal çalışan ve sınırlandırılmış regex kalıbı
// Sadece tek seviyeli bir artı (+) işareti kullanılmış, gruplar birbirinden izole edilmiştir.
const SAFE_EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;

// Tasarlanan kalıbın ReDoS riskine sahip olup olmadığı statik olarak denetleniyor
if (!safeRegex(SAFE_EMAIL_REGEX)) {
    console.warn("Kritik Uyarı: Kullanılan regex kalıbı ReDoS açığı barındırıyor olabilir!");
}
 
app.post('/api/register', (req, res) => {
    const { email } = req.body;
 
    if (!email) {
        return res.status(400).json({ error: "E-posta adresi zorunludur." });
    }
 
    // 1. GÜVENLİK Sınırı: Girdinin uzunluğu regex işlemine girmeden önce kısıtlanıyor
    // Saldırganın çok uzun metinler göndererek işlemciyi yorması en başta engellenir
    if (email.length > 100) {
        return res.status(400).json({ error: "Geçersiz e-posta adresi: Çok uzun girdi." });
    }
 
    // 2. GÜVENLİ YAPI: Sıkılaştırılmış ve doğrusal zamanlı regex doğrulaması
    const isValid = SAFE_EMAIL_REGEX.test(email);
 
    if (!isValid) {
        return res.status(400).json({ error: "Geçersiz e-posta formatı." });
    }
 
    return res.status(200).json({ message: "Kayıt güvenli bir şekilde tamamlandı." });
});
 
app.listen(3000);
```
🧱 Savunma Katmanları (Defense-in-Depth)Regex doğrulamalarının güvenliğini ve sistem direncini en üst seviyeye çıkarmak için şu ek koruma katmanları uygulanmalıdır:1. Güvenli ve Doğrusal (Lineer) Regex Motorlarının KullanımıSistemlerde kullanılan varsayılan programlama dili motorlarının (NFA) yerine, doğrusal arama garantisi sunan kütüphaneler tercih edilmelidir.🚀 Google RE2 Motoru: Google tarafından geliştirilen RE2 regex motoru, backtracking mekanizması yerine DFA (Deterministic Finite Automaton) mimarisini kullanır. RE2, girdinin uzunluğundan bağımsız olarak her zaman $O(n)$ zaman karmaşıklığında çalışacağını matematiksel olarak garanti eder ve ReDoS saldırılarına karşı mutlak koruma sağlar.🛠️ Kütüphane Entegrasyonu: Node.js projelerinde re2 npm paketi, Go ve Python projelerinde ise yerleşik RE2 sarmalayıcıları (wrappers) kullanılmalıdır.2. Kalıp Analiz Araçları ve Statik Kod Analizi (SAST)Yazılım geliştirme süreçlerinde (CI/CD hatlarında) kullanılan regex kalıpları otomatik olarak taranmalıdır.🔍 Regex Analiz Araçları: Geliştirilen kalıplar; safe-regex (Node.js), rxxr2 veya vuln-regex-detector gibi araçlarla statik analize tabi tutulmalıdır.🛡️ SAST Entegrasyonu: SonarQube, Semgrep veya Snyk gibi statik kod analiz araçları, kod tabanındaki potansiyel olarak tehlikeli ve "felaketsel geriye doğru takibe" (catastrophic backtracking) yol açabilecek regex kalıplarını geliştirme aşamasında tespit ederek derlemeyi durduracak şekilde yapılandırılmalıdır.3. Kalıpların Sadeleştirilmesi ve Zaman Aşımı (Timeout) Yapılandırması🧹 Gruplamaların Temizlenmesi: Kalıplar tasarlanırken (a*)*, (a+)+, (a|b+)+ veya (a|a)+ gibi "tekrarlanan tekrarlar" (nested quantifiers) barındıran yapılardan kesinlikle kaçınılmalıdır. Her grup kendi içinde net, benzersiz ve çakışmayan (non-overlapping) karakter kümelerini hedef almalıdır.⏱️ Zaman Aşımı (Timeout) Sınırlandırması: .NET Core gibi bazı modern platformlar, regex eşleştirme fonksiyonlarına yerleşik bir zaman aşımı (Timeout) parametresi eklenmesine izin verir. Regex doğrulama işlemine maksimum 100-200 milisaniyelik bir çalışma limiti atanmalı; bu süreyi aşan karmaşık aramalar işletim sistemi seviyesinde otomatik olarak kesilerek işlemcinin kilitlenmesi önlenmelidir.








# 🛡️ 3. Race Condition (Yarış Durumu Açıkları)

Bir sistemin, uygulamanın veya veri tabanının güvenliğinin ve iş mantığı kararlarının, birden fazla işlemin tam olarak hangi sıra veya zamanlama ile tamamlanacağına bağımlı olması durumunda ortaya çıkan tasarımsal zafiyet türüne **Race Condition** denir.

> ⏱️ **TOCTOU Penceresi:** Bu zafiyette siber saldırgan, sunucunun bir işlem talebini aldığı an ile o işlemin veri tabanına nihai olarak yazıldığı (*Commit*) an arasında geçen milisaniyelik zamanlama boşluğunu (**Time-of-Check to Time-of-Use - TOCTOU**) suistimal eder. 

Saldırgan, otomatize scriptler vasıtasıyla sunucuya mikro saniyeler farkla onlarca eş zamanlı (*concurrent*) istek fırlatır. Sunucu, ilk isteğin bakiyeyi düşürme veya durumu "kullanıldı" olarak işaretleme işlemini henüz tamamlayamadan ikinci, üçüncü ve dördüncü istekleri de okur. Sonuç olarak sistem, tek bir hakka veya bakiyeye sahip olan kullanıcının bu hakkı eş zamanlı olarak defalarca kez sömürmesine izin verir. Bu durum; bankacılık transferlerinde mükerrer para çekmeye, e-ticaret sitelerinde hediye kuponlarının sınırsız kez kullanılmasına ve oylama sistemlerinin manipüle edilmesine yol açar.

---

## 🔍 Race Condition Zafiyetlerinin Teknik Anatomisi (TOCTOU)

Yarış durumu açıkları, eş zamanlı çalışan iş parçacıklarının (*threads*) veya işlemlerin (*processes*) paylaşılan ortak bir kaynağa (veri tabanı hücresi, bellek adresi, dosya sistemi) aynı anda erişip güncelleme yapmaya çalışmasından (**Shared State**) beslenir. Süreç genellikle şu aşamalarla sömürülür:

1.  🔍 **Kontrol Zamanı (Time of Check):** Kullanıcı bir kupon kodu girdiği an sunucu veri tabanına sorar: *"Bu kupon daha önce kullanıldı mı?"* Veri tabanı yanıt verir: *"Hayır, henüz kullanılmadı."*
2.  🔓 **Saldırı Aralığı (The Window of Vulnerability):** Sunucu, kuponun kullanılmadığını onayladıktan sonra kupon değerini kullanıcının cüzdanına ekleme ve veri tabanındaki kupon durumunu "kullanıldı" olarak güncelleme işlemlerini sırayla başlatır. Bu iki işlem arasında milisaniyelik bir gecikme yaşanır.
3.  ⚡ **Kullanım Zamanı (Time of Use):** Saldırgan, bu milisaniyelik boşlukta 50 adet eş zamanlı istek fırlatmıştır. İkinci istek sunucuya ulaştığında, ilk istek henüz kupon durumunu "kullanıldı" olarak güncelleyemediği için, sunucu ikinci isteğin kontrol aşamasında da *"Hayır, kullanılmadı"* yanıtını alır ve kuponu bir kez daha cüzdana tanımlar.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code - Node.js / PostgreSQL)
Aşağıdaki Node.js ve Express örneğinde, bir kullanıcının hesabındaki parayı başka bir kullanıcıya transfer etmesini sağlayan bir API uç noktası yer almaktadır. Kod, bakiye kontrolü yapıyor olsa da eş zamanlı gelen isteklerin veri tabanını aynı anda okumasını engelleyecek hiçbir kilitleme (*locking*) mekanizması barındırmamaktadır:

```javascript
const express = require('express');
const app = express();
const pool = require('./dbPool'); // PostgreSQL Bağlantı Havuzu
app.use(express.json());

// GÜVENSİZ YAPI: Eş zamanlı isteklerde bakiye güncellenmeden önce birden fazla 
// okuma yapılmasına izin verilir (Race Condition zafiyeti)
app.post('/api/transfer', async (req, res) => {
    const { receiverId, amount } = req.body;
    const senderId = req.user.id;
 
    try {
        // 1. KONTROL AŞAMASI (Time of Check)
        const senderQuery = await pool.query('SELECT balance FROM users WHERE id = $1', [senderId]);
        const currentBalance = senderQuery.rows[0].balance;
 
        if (currentBalance < amount) {
            return res.status(400).json({ success: false, error: "Yetersiz bakiye." });
        }
 
        // Yapay Gecikme Simülasyonu (Veri tabanı yoğunluğu veya ağ gecikmesi)
        await new Promise(resolve => setTimeout(resolve, 50));
 
        // 2. KULLANIM AŞAMASI (Time of Use)
        // Göndericinin bakiyesi düşürülüyor
        await pool.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [amount, senderId]);
        // Alıcının bakiyesi artırılıyor
        await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [receiverId]);
 
        return res.status(200).json({ success: true, message: "Transfer başarıyla tamamlandı." });
    } catch (error) {
        return res.status(500).json({ success: false, error: "Sistem hatası." });
    }
});
 
app.listen(3000);
```
🎯 Saldırı Senaryosu
Saldırganın hesabında sadece 100 TL bakiye bulunmaktadır.

Saldırgan, otomatize bir script hazırlayarak /api/transfer adresine mikro saniyeler farkla 10 adet eş zamanlı istek fırlatır.

Gelen ilk 5 istek, bakiye henüz düşürülmeden önce bakiye okuma sorgusunu (SELECT balance) çalıştırır. Hepsi de bakiyeyi "100 TL" olarak görür.

Koşul sağlandığı için 5 istek de onay alır ve arka arkaya bakiye düşürme sorgularını çalıştırır.

Sonuç: Saldırgan, 100 TL'si olduğu halde alıcı hesaba toplamda 500 TL transfer etmeyi başarır ve kendi bakiyesi negatif bakiye sınırlarını aşarak eksiye düşer.

🔐 Doğru ve Güvenli Kod (Secure Code)
Race Condition zafiyetlerini önlemenin en kesin yöntemi, veri tabanı seviyesinde satır kilitleme (Row Locking / Pessimistic Locking) yöntemlerini kullanmaktır. Okuma işlemi yapıldığı an ilgili satır kilitlenmeli, işlem tamamen bitip Commit edilene kadar diğer eş zamanlı isteklerin o satırı okuması veya güncellemesi engellenmelidir.
```javascript
const express = require('express');
const app = express();
const pool = require('./dbPool');
app.use(express.json());
 
app.post('/api/transfer', async (req, res) => {
    const { receiverId, amount } = req.body;
    const senderId = req.user.id;
    
    // Güvenlik doğrulaması
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ success: false, error: "Geçersiz miktar." });
    }
 
    // GÜVENLİ YAPI: İşlemler bir Transaction bloğu içerisinde yürütülüyor
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Transaction başlatılıyor
 
        // GÜVENLİ YAPI: "FOR UPDATE" ifadesi ile satır seviyesinde Pessimistic Lock (Kötümser Kilitleme) uygulanıyor.
        // Bu sorgu çalıştığı an, senderId'ye ait satır kilitlenir. Eş zamanlı gelen diğer istekler, 
        // bu transaction COMMIT veya ROLLBACK olana kadar bekletilir (blocklanır), eski veriyi okuyamazlar.
        const senderQuery = await client.query(
            'SELECT balance FROM users WHERE id = $1 FOR UPDATE', 
            [senderId]
        );
        const currentBalance = senderQuery.rows[0].balance;
 
        if (currentBalance < parsedAmount) {
            await client.query('ROLLBACK'); // İşlem iptal ediliyor, kilit kaldırılıyor
            return res.status(400).json({ success: false, error: "Yetersiz bakiye." });
        }
 
        // Gönderici bakiyesi düşürülüyor
        await client.query(
            'UPDATE users SET balance = balance - $1 WHERE id = $2', 
            [parsedAmount, senderId]
        );
        
        // Alıcı bakiyesi artırılıyor
        await client.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2', 
            [parsedAmount, receiverId]
        );
 
        await client.query('COMMIT'); // İşlem veri tabanına yazılıyor, kilitler güvenli bir şekilde serbest bırakılıyor
        return res.status(200).json({ success: true, message: "Transfer güvenli bir şekilde tamamlandı." });
    } catch (error) {
        await client.query('ROLLBACK'); // Hata durumunda tüm değişiklikler geri alınıyor
        return res.status(500).json({ success: false, error: "İşlem gerçekleştirilemedi." });
    } finally {
        client.release(); // Veri tabanı bağlantısı havuza geri iade ediliyor
    }
});
 
app.listen(3000);
```
🧱 Savunma Katmanları (Defense-in-Depth)
Zamanlama ve eş zamanlılık kaynaklı mantıksal açıkları tamamen izole etmek adına sistem mimarisinde şu ek koruma katmanları kurgulanmalıdır:

1. İşlemlerin Atomikliği ve Benzersiz Kısıtlar (Database Constraints)
Veri tabanında durum güncellemeleri yapılırken doğrudan atomik SQL komutlarından yararlanılmalıdır. Bakiye doğrulaması yapıp ardından yeni bakiyeyi hesaplayıp set etmek yerine, SQL'in tek bir satırda çalıştırdığı atomik güncellemeler tercih edilmelidir:

SQL
UPDATE users SET balance = balance - 100 WHERE id = 5 AND balance >= 100;
Atomik İşlem: Bu sorgu, bakiye kontrolünü ve güncellemeyi veri tabanı motoru seviyesinde tek bir mikro saniyede (atomik olarak) gerçekleştirir. Eğer koşul (balance >= 100) sağlanmıyorsa hiçbir satır güncellenmez ve etkilenen satır sayısı sıfır döner. Sunucu bu dönüş değerine göre işlemi iptal edebilir.

2. Kod Seviyesinde Senkronizasyon (Mutex / Dağıtık Kilitleme)
Birden fazla sunucunun (cluster) veya mikroservisin aktif çalıştığı yüksek trafikli dağıtık mimarilerde, veri tabanı kilitleri yetersiz kalabilir.

🔒 Dağıtık Kilitleme (Distributed Locking): Redis benzeri hızlı bellek içi veri depoları kullanılarak Redlock algoritması veya Mutex/Semaphore yapıları kurulmalıdır.

🔑 Kilit Mekanizması: Bir kullanıcı kritik bir işlem başlattığı an, kullanıcının ID değeri anahtar yapılarak Redis üzerinde geçici bir kilit oluşturulur (SET user_lock_12 EX 5 NX komutu ile). Eş zamanlı gelen diğer istekler bu anahtarın varlığını gördüğü an işlemi sunucu katmanında anında reddeder. İşlem bittiğinde kilit kaldırılır.

3. İstek Hızı Sınırlama (Rate Limiting) ve Mesaj Kuyrukları (Message Queues)
Saldırganın milisaniyeler içerisinde yüzlerce istek gönderme kabiliyeti ağın girişinde engellenmelidir.

📥 Kuyruk Yönetimi (FIFO): Eş zamanlı çalıştırılması risk teşkil eden hassas işlemler (bilet satışı, stok eritme vb.) doğrudan senkron olarak işlenmemelidir. Gelen talepler RabbitMQ, Apache Kafka veya AWS SQS gibi bir mesaj kuyruğuna (Message Queue) fırlatılmalıdır.

🏎️ Sıralı Tüketim: Kuyruk, gelen istekleri kesin bir şekilde geliş sırasına göre (First-In-First-Out / FIFO) tek bir iş parçacığı (single-threaded consumer) vasıtasıyla sırayla işler. Böylece işlemler arasında hiçbir zaman zamanlama çakışması veya yarış durumu yaşanamaz.




# 🛡️ 4. Insufficient Logging & Monitoring (Yetersiz Günlükleme ve İzleme)

Sistem mimarilerinde veya uygulama katmanlarında gerçekleşen siber saldırıların, yetkisiz erişim teşebbüslerinin, veri sızıntılarının ve anomali gösteren sistem hareketlerinin kayıt altına alınmaması, analiz edilmemesi veya gerçek zamanlı olarak izlenmemesi sonucu ortaya çıkan; saldırının tespit edilme süresini (**Mean Time to Detect - MTTD**) uzatan ve adli bilişim (*forensics*) süreçlerini imkansız kılan kritik bir operasyonel/tasarımsal zafiyet kategorisidir.

> 🔍 **Sessiz Tehdit:** Yetersiz günlükleme ve izleme, doğrudan bir hacker'ın içeri sızmasını sağlayan bir açık (SQLi veya RCE gibi) değildir. Ancak, saldırganın sistemde aylarca fark edilmeden kalmasına, yatayda hareket ederek (*lateral movement*) diğer sunucuları ele geçirmesine ve sızdırdığı verilerin izini tamamen kaybettirmesine zemin hazırlar. 

Güvenlik ekiplerinin sisteme karşı tamamen "kör" kalmasına neden olan bu durum, dünya genelindeki büyük veri ihlallerinde saldırganların içeride ortalama **200 günden fazla** tespit edilmeden kalabilmesinin ana sebebidir.

---

## 🔍 Yetersiz Günlükleme ve İzlemenin Teknik Anatomisi

Saldırganlar, hedef sistemde iz bırakmadan hareket etmek ve keşif faaliyetlerini gizlemek için bu zafiyetten şu şekillerde faydalanırlar:

*   🚫 **Log Eksikliği (No Logs):** Giriş denemeleri, şifre sıfırlama talepleri veya veri tabanı güncellemeleri gibi kritik olayların hiçbir şekilde kayıt altına alınmaması.
*   ❔ **Adli Bilişim Boşlukları (Lack of Context):** Logların tutulması fakat detay içermemesi. Örneğin, sadece "Hatalı Giriş" yazılması; bu girişin hangi IP adresinden, hangi kullanıcı adına, ne zaman ve hangi tarayıcı parmak iziyle yapıldığının kaydedilmemesi.
*   🧹 **Log Manipülasyonu (Log Tampering):** Log dosyalarının yerel sunucuda düz metin (*plain-text*) olarak saklanması. Sunucuya sızan bir saldırgan, işi bittiğinde `/var/log/` altındaki kayıtları silerek veya değiştirerek geriye dönük analizi tamamen imkansız hale getirebilir.
*   ⏳ **Pasif İzleme ve Alarmsızlık:** Loglar devasa boyutlarda tutulsa bile, saniyede binlerce hatalı giriş alan bir sisteme karşı otomatik bir alarm (*Alerting*) veya engelleme mekanizmasının olmaması.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code - Node.js)
Aşağıdaki Express.js örneğinde, bir uygulamanın şifre sıfırlama (*password reset*) uç noktası yer almaktadır. Yazılımcı, işlem esnasında olası hataları konsola basmış ancak adli analize imkan tanıyacak veya bir saldırıyı erkenden haber verecek hiçbir yapılandırılmış (*structured*) güvenlik günlüğü (*security log*) oluşturmamıştır:

```javascript
const express = require('express');
const app = express();
const db = require('./dbConnection');
app.use(express.json());

// GÜVENSİZ YAPI: Kritik bir işlemde hiçbir güvenlik logu üretilmiyor.
// Olası bir hata durumunda ise sadece jenerik metin konsola yazılıyor.
app.post('/api/auth/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
 
    try {
        const user = await db.findUserByEmail(email);
        if (!user) {
            // Sadece HTTP yanıtı dönülüyor, olay hiçbir yere kaydedilmiyor.
            // Saldırgan bu uç noktada binlerce e-posta adresi deneyerek hesap taraması (user enumeration) yapabilir.
            return res.status(400).json({ success: false, message: "İşlem başarısız." });
        }
 
        await db.updatePassword(user.id, newPassword);
        
        // GÜVENSİZ: Sadece terminale basit bir metin basılıyor (Kalıcı değil, rotasyonsuz, detaysız)
        console.log("Şifre güncellendi."); 
        
        return res.status(200).json({ success: true, message: "Şifreniz başarıyla sıfırlandı." });
    } catch (error) {
        // GÜVENSİZ: Hata detayı terminale basılıyor ancak yapılandırılmış (structured JSON) değil.
        // IP adresi, istek atan kullanıcı gibi bağlamsal bilgiler eksik.
        console.error("Şifre sıfırlama hatası:", error.message);
        return res.status(500).json({ success: false, message: "Sistem hatası." });
    }
});
 
app.listen(3000);
```
🎯 Saldırı ve Tespit Zayıflığı Senaryosu
Saldırgan, sisteme kayıtlı tüm e-postaları tespit etmek için bir bot vasıtasıyla bu uç noktaya saniyede 500 farklı istek fırlatır.

Uygulama tarafında bu istekleri analiz edecek veya log sunucusuna standardı belirlenmiş bir biçimde paslayacak bir mekanizma olmadığı için, saldırgan hiçbir engele veya alarma takılmadan saatlerce hesap taraması yapar.

Sonuç: Olayın ardından adli bilişim ekibi sunucuyu incelediğinde, saldırganın hangi IP adreslerini kullandığını veya hangi hesapları ele geçirdiğini yerel konsol çıktılarından asla analiz edemez.

🔐 Doğru ve Güvenli Kod (Secure Code)
Güvenli bir yapıda, tüm kritik güvenlik olayları yapılandırılmış (Structured JSON) biçimde, bağlamsal verilerle (IP, User-Agent, Session ID, User ID) birlikte, yerel konsola değil, merkezi bir log yönetim sistemine aktarılacak şekilde (Winston, Bunyan gibi profesyonel kütüphaneler kullanılarak) loglanmalıdır.

```javascript
const express = require('express');
const winston = require('winston'); // Yapılandırılmış loglama kütüphanesi
const app = express();
app.use(express.json());

// GÜVENLİ YAPI: Winston log motoru yapılandırılıyor.
// Loglar JSON formatında üretilir, böylece SIEM veya Elasticsearch gibi araçlar tarafından kolayca okunup dizinlenir.
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'auth-service' },
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'logs/security.log', level: 'warn' }) // Kritik olaylar dosyaya yazılır
    ]
});
const db = require('./dbConnection');
 
app.post('/api/auth/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
    const clientIp = req.ip;
    const userAgent = req.headers['user-agent'];
 
    try {
        const user = await db.findUserByEmail(email);
        if (!user) {
            // GÜVENLİ YAPI: Şüpheli hesap tarama teşebbüsü bağlamsal verilerle WARN seviyesinde kaydediliyor
            logger.warn({
                event: 'password_reset_failed_user_not_found',
                requested_email: email,
                ip: clientIp,
                userAgent: userAgent,
                timestamp: new Date().toISOString()
            });
            return res.status(400).json({ success: false, message: "İşlem gerçekleştirilemedi." });
        }
 
        await db.updatePassword(user.id, newPassword);
 
        // GÜVENLİ YAPI: Başarılı şifre değişikliği INFO seviyesinde kaydediliyor (Kritik Hesap Değişikliği)
        logger.info({
            event: 'password_reset_success',
            userId: user.id,
            email: user.email,
            ip: clientIp,
            userAgent: userAgent,
            timestamp: new Date().toISOString()
        });
 
        return res.status(200).json({ success: true, message: "Şifreniz sıfırlandı." });
    } catch (error) {
        // GÜVENLİ YAPI: Sistem hataları ERROR seviyesinde tüm stack trace detayıyla loglanıyor
        logger.error({
            event: 'password_reset_system_error',
            error: error.message,
            stack: error.stack,
            ip: clientIp,
            timestamp: new Date().toISOString()
        });
        return res.status(500).json({ success: false, message: "Sistem hatası." });
    }
});
 
app.listen(3000);
```
🧱 Savunma Katmanları (Defense-in-Depth)
Loglama ve izleme güvenliğini üst seviyeye çıkarmak ve bir siber saldırıyı saniyeler içinde fark edip müdahale edebilmek amacıyla şu ek savunma katmanları kurulmalıdır:

1. Nelerin Loglanacağını Doğru Belirlemek (Log Scope)
Log yönetimi sadece sistem çökmelerini (Exceptions) kaydetmekten ibaret görülmemelidir. Güvenlik odaklı bir mimaride şu olaylar kesinlikle izlenmeli ve loglanmalıdır:

🔑 Kimlik Doğrulama Olayları: Başarılı ve başarısız tüm giriş denemeleri, şifre sıfırlama, e-posta değiştirme ve iki faktörlü doğrulama (MFA) güncellemeleri.

🚫 Yetki Sınırlarının Aşılması: Kullanıcıların yetkisi olmayan sayfalara erişmeye çalışırken tetiklediği HTTP 401 (Unauthorized) ve HTTP 403 (Forbidden) hataları.

⚠️ Girdi Doğrulama Patlamaları: Girdi doğrulama (input validation) katmanında patlayan parametre veya mantık hataları. Bu hatalar genellikle saldırganların sisteme SQLi, XSS veya Path Traversal gibi payload'lar fırlatarak yaptığı keşif hareketlerinin (scanning) habercisidir.

💼 Hassas Veri Erişimleri: Yüksek tutarlı finansal transferler, toplu veri indirmeleri (export) veya admin paneli üzerinden yapılan kritik yapılandırma değişiklikleri.

2. Hassas Verilerin Maskelenmesi ve Log Bütünlüğü (WORM)
Logların hem kendisi güvenli olmalı hem de içerdikleri veriler yasal uyumluluklara (KVKK/GDPR/PCI-DSS) uygun olmalıdır.

📝 Log Maskeleme (Log Masking): Kullanıcı şifreleri, kredi kartı numaraları, API gizli anahtarları (secrets) veya kişisel veriler log dosyalarına asla ham metin olarak yazılmamalıdır. Bu veriler daha log motoruna ulaşmadan regex yardımıyla maskelenmelidir (XXXX-XXXX-XXXX-1234).

📦 Merkezi ve Sadece Yazılabilir (WORM) Loglama: Log dosyaları web sunucusunun kendi yerel diskinde düz metin olarak tutulmamalıdır. Tüm loglar gerçek zamanlı olarak ağ üzerinden SIEM (Security Information and Event Management) veya log sunucularına (ELK Stack, Splunk vb.) aktarılmalıdır. Log sunucuları sadece yazılabilir, silinemez ve değiştirilemez (WORM - Write Once Read Many) kurallarıyla yapılandırılmalıdır. Böylece, sunucuyu ele geçiren saldırgan kendi log izlerini silmeye çalışsa dahi, kayıtlar çoktan merkezi SIEM sunucusuna aktarıldığı için başarılı olamaz.

3. Gerçek Zamanlı Alarm, Eşik Değer Politikaları ve Davranış Analizi
Logların sadece toplanması yetmez; bu verileri analiz eden dinamik alarm mekanizmaları kurulmalıdır.

🚨 Eşik Değer (Threshold) Alarmları: Sistemde belirli limitler tanımlanmalıdır. Örneğin: "Aynı IP adresinden 5 dakika içinde 20'den fazla başarısız giriş denemesi yapılırsa" veya "Aynı kullanıcı 10 dakika içinde 5 farklı IP'den oturum açmaya çalışırsa" ilgili IP'yi otomatik olarak banla ve güvenlik ekibine (SOC) anlık alarm fırlat.

⚙️ Korelasyon Kuralları (Correlation Rules): SIEM üzerinde karmaşık siber saldırı senaryolarını yakalayacak kurallar yazılmalıdır. Örneğin; sunucuda önce bir SQL hatası tetiklenmesi, hemen ardından /etc/passwd okunmaya çalışılması ve ardından ağdan dışarıya büyük boyutta veri transferi (Egress Traffic) gerçekleşmesi durumunda, bu zincirleme hareket "Aktif Veri Sızıntısı Saldırısı" olarak etiketlenmeli ve sunucu ağ bağlantısı otomatik olarak izole edilmelidir.
