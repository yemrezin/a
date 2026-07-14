# 🛡️ 1. Business Logic Vulnerabilities (İş Mantığı Açıkları)

Uygulamanın kaynak kodundaki geleneksel bir yazılımsal zafiyeti (SQL Injection, XSS, Buffer Overflow vb.) sömürmek yerine; sistemin iş kuralları, süreç akışları, tasarımsal adımları veya mantıksal kabullerindeki boşlukların manipüle edilerek sistemin amacına tamamen aykırı işlemler gerçekleştirilmesine olanak tanıyan tasarımsal zafiyet türüne **Business Logic Vulnerabilities** denir.

> 🔍 **Otomatik Tarayıcıların Sınırı:** Bu zafiyet türü, tarayıcılar veya otomatik siber güvenlik tarama araçları (DAST/SAST) tarafından otomatik olarak tespit edilemez. Çünkü siber saldırganın gönderdiği isteklerin tamamı teknik açıdan (*syntactically*) meşru ve kusursuzdur; sistemin standart siber güvenlik filtrelerini (WAF) kolayca geçer. 

Tehlike, sunucunun bu istekleri iş mantığı katmanında (*business logic layer*) yorumlama şeklinden ve adımlar arasındaki mantıksal kopukluklardan kaynaklanır. Saldırganlar bu açıkları kullanarak e-ticaret sitelerinden bedavaya veya negatif fiyatlarla ürün satın alabilir, kupon kodlarını sınırsız kez döngüye sokabilir, bankacılık uygulamalarında onay adımlarını atlayabilir veya dikey/yatay yetki sınırlarını aşabilirler.

---

## 🔍 İş Mantığı Açıklarının Teknik Anatomisi

İş mantığı zafiyetleri genellikle yazılım mimarlarının ve analistlerin sistem tasarım aşamasında *"kullanıcının sadece arayüzün izin verdiği adımları takip edeceği"* varsayımına güvenmelerinden beslenir. Saldırganlar ise arayüzü (UI) tamamen devre dışı bırakıp doğrudan HTTP isteklerini manipüle ederek şu zayıflıkları sömürürler:

*   ⏭️ **Süreç Atlama (Workflow Bypass):** Bir e-ticaret akışının *Ürün Seçimi -> Sepet -> Adres Tanımlama -> Ödeme -> Sipariş Onay* şeklinde 5 adımdam oluştuğunu varsayalım. Eğer sunucu, 5. adıma gelen isteğin arkasındaki kullanıcının 4. adımdaki ödeme işlemini başarıyla tamamlayıp tamamlamadığını kendi veri tabanında doğrulamıyorsa; saldırgan doğrudan 5. adıma ait HTTP POST isteğini fırlatarak ödeme yapmadan sipariş oluşturabilir.
*   📉 **Negatif Değer / Sınır İhlali (Numerical Range Underflow):** Alışveriş sepeti güncellenirken sunucuya gönderilen ürün adet veya fiyat parametreleri negatif değerlerle (`quantity: -1`) test edilir. Eğer arka uçta *"girdinin pozitif tamsayı olması gerektiği"* kuralı işletilmiyorsa, toplam sepet tutarı düşürülerek sistem sıfır veya eksi bakiyeyle siparişi onaylamaya zorlanabilir.
*   🎭 **Durum Değişkeni Manipülasyonu:** Kullanıcı kayıt veya profil güncelleme aşamasında HTTP gövdesine eklenen gizli parametrelerle (örneğin `{"username": "ali", "is_premium": true}`) sistemin ödeme kontrol adımları bypass edilir.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code)
Aşağıdaki Node.js, Express Genel ve Sequelize (ORM) örneğinde, bir e-ticaret sisteminde sepet güncelleme eylemini gerçekleştiren API uç noktası yer almaktadır. Yazılımcı, teknik olarak parametreli sorgu kullanmış ve SQLi riskini önlemiştir; ancak kullanıcının gönderdiği ürün adet bilgisinin mantıksal sınırını denetlememiştir:

```javascript
const express = require('express');
const app = express();
app.use(express.json());
 
const { Cart, Product } = require('./models');
 
// GÜVENSİZ YAPI: Kullanıcıdan gelen adet (quantity) parametresinin mantıksal doğruluğu taranmıyor
app.post('/api/cart/update', async (req, res) => {
    try {
        const { productId, quantity } = req.body;
        const userId = req.user.id; // Oturum açmış kullanıcının ID'si
        
        // Ürün bilgisi çekiliyor
        const product = await Product.findByPk(productId);
        if (!product) {
            return res.status(404).json({ error: "Ürün bulunamadı." });
        }
        
        // GÜVENSİZ YAPI: Negatif sayı kontrolü yok!
        // Saldırgan adet bilgisini eksi değer göndererek toplam sepet tutarını düşürebilir.
        const totalPrice = product.price * quantity;
        
        // Sepet kaydı güncelleniyor veya oluşturuluyor
        await Cart.upsert({
            userId,
            productId,
            quantity,
            totalPrice
        });
        
        return res.status(200).json({ success: true, message: "Sepet güncellendi." });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});
 
app.listen(3000);
```
🎯 Saldırı Senaryosu
Saldırgan sepetine 1500 TL değerinde 1 adet bilgisayar ekler.

Ardından sepetine 5 TL değerinde olan ucuz bir kalemden daha ekler ve kalem güncelleme isteğini proxy aracıyla keserek gövdeyi şu şekilde manipüle eder:
```json
{
  "productId": 2, 
  "quantity": -200
}
```
Uygulamanın arka planda yaptığı mantıksal hesaplama şu şekle bürünür:

Toplam Tutar = (1 * 1500) + (-200 * 5) => 1500 - 1000 = 500 TL

Sonuç: Sistem, toplam sepet tutarını 500 TL olarak günceller. Saldırgan ödeme aşamasına geçerek 1500 TL'lik bilgisayarı 500 TL ödeyerek yasal olarak satın alır.

🔐 Doğru ve Güvenli Kod (Secure Code)
İş mantığı açıklarını önlemek için kullanıcıdan gelen tüm girdilerin mantıksal sınırları, iş kuralları ve veri tutarlılıkları sunucu tarafında her işlem adımında katı bir şekilde doğrulanmalıdır (Server-Side State Validation).
```javascript
const express = require('express');
const app = express();
app.use(express.json());
 
const { Cart, Product } = require('./models');
 
app.post('/api/cart/update', async (req, res) => {
    try {
        const { productId, quantity } = req.body;
        const userId = req.user.id;
        
        // 1. Girdi Validasyonu: Adet bilgisi tamsayı olmalı ve 1 ile 99 arasında kalmalıdır
        const parsedQuantity = parseInt(quantity, 10);
        if (isNaN(parsedQuantity) || parsedQuantity <= 0 || parsedQuantity > 99) {
            return res.status(400).json({ error: "Geçersiz ürün adeti." });
        }
        
        const product = await Product.findByPk(productId);
        if (!product) {
            return res.status(404).json({ error: "Ürün bulunamadı." });
        }
        
        // 2. İş Mantığı Doğrulaması: Stok kontrolü sunucu tarafında doğrulanıyor
        if (product.stock < parsedQuantity) {
            return res.status(400).json({ error: "Yetersiz stok." });
        }
        
        // GÜVENLİ YAPI: Doğrulanmış ve sınırlandırılmış temiz veriyle hesaplama yapılıyor
        const totalPrice = product.price * parsedQuantity;
        
        await Cart.upsert({
            userId,
            productId,
            quantity: parsedQuantity,
            totalPrice
        });
        
        return res.status(200).json({ success: true, message: "Sepet güvenli bir şekilde güncellendi." });
    } catch (error) {
        return res.status(500).json({ error: "İşlem gerçekleştirilemedi." });
    }
});
 
app.listen(3000);
```
🧱 Savunma Katmanları (Defense-in-Depth)
Mantıksal zafiyetlerin karmaşık yapısını engellemek ve sistem akış güvenliğini sağlamlaştırmak adına şu derinlemesine savunma ilkeleri uygulanmalıdır:

1. Güvenli Durum ve Veri Akışı Yönetimi (State Machine Validation)
Kullanıcıların işlemler esnasındaki durum geçişleri sunucu tarafında katı kurallara bağlı bir durum makinesi (State Machine) mantığıyla yönetilmelidir.

🚫 İstemci Parametrelerine Güvenmeyin: Süreç adımları sadece istemci tarafında tutulan parametrelerle (örneğin URL'deki step=4 parametresiyle) takip edilmemelidir.

💾 Sunucu Taraflı Durum Takibi: Her kritik adım tamamlandığında, sunucu tarafındaki kullanıcı oturumuna (Session) veya veri tabanına kriptografik olarak doğrulanmış durum bayrakları (örneğin is_payment_verified = true) yazılmalı ve bir sonraki adıma geçiş talebi geldiğinde bu bayrakların varlığı sunucuda sıfırdan sorgulanmalıdır.

2. İşlemlerin Atomikliği (Database Transactions)
Birden fazla tablonun güncellenmesini gerektiren zincirleme mantık adımlarında, veri tabanı seviyesinde ACID (Atomicity, Consistency, Isolation, Durability) ilkelerine uygun işlemler kullanılmalıdır.

⚖️ Birlikte Başarı veya Birlikte İptal: Bir para transferi veya puan harcama akışında; kullanıcının bakiyesinin düşülmesi adımı ile hak tanımlanması adımı tek bir veri tabanı işlemi (Transaction) bloğuna alınmalıdır.

🔄 Rollback Mekanizması: Süreç adımlarından herhangi birinde bir hata veya mantıksal tutarsızlık yaşanırsa, veri tabanı Rollback komutuyla tüm süreci en başa sarmalı; bakiyenin düşüp hakkın tanımlanmaması gibi kısmi işlem sömürülerine (race condition / asynchronous exploits) izin verilmemelidir.

3. Tehdit Modelleme ve Sürekli Mantık Testleri (Business Logic Testing)
Yazılım geliştirme döngüsünde (SDLC) iş mantığı açıklarını yakalamak için teknik analizlerin ötesine geçilmelidir.

🧠 Tehdit Modelleme (Threat Modeling): Tasarım aşamasında "Bu özellik nasıl istismar edilebilir? Kullanıcı adımları tersine işletirse ne olur? Birden fazla sekmeyle aynı anda istek atarsa ne olur?" soruları sorularak risk senaryoları çıkarılmalıdır.

🧪 Mantıksal Birim Testleri (Unit/Integration Tests): Sadece sistemin düzgün çalışmasını ölçen olumlu testler değil; sınır dışı değerleri, negatif sayıları, yetkisiz istek geçişlerini ve eş zamanlı istekleri (Race Condition) taklit eden olumsuz test senaryoları da sürekli entegrasyon (CI) süreçlerine dahil edilmelidir.

# 🛡️ 2. Software and Data Integrity Failures (Yazılım ve Veri Bütünlüğü Hataları)

Uygulamaların, altyapıların ve dağıtım hatlarının, harici kod kütüphanelerini, veri dosyalarını veya yazılım güncelleme paketlerini sistem bünyesine dahil ederken bunların kaynak doğruluğunu ve içerik bütünlüğünü doğrulamaması sonucu ortaya çıkan kritik güvenlik zafiyetleri kategorisine **Software and Data Integrity Failures** denir.

> 🔄 **Yaşam Döngüsü Güvenliği:** Bu zafiyet kategorisi, yazılımın yalnızca yazıldığı andaki güvenliğini değil; geliştirme, paketlenme, dağıtılma ve çalışma zamanındaki (*runtime*) tüm yaşam döngüsünü kapsar.

Günümüz yazılım dünyasında uygulamalar, yüzlerce hatta binlerce üçüncü parti kütüphaneye (npm, NuGet, Maven, pip paketleri) ve harici servis entegrasyonuna bağımlıdır. Siber saldırganlar, doğrudan hedef kurumu hacklemek yerine, kurumun kullandığı popüler bir açık kaynak kütüphaneyi ele geçirerek (**Tedarik Zinciri Saldırısı - Supply Chain Attack**) veya otomatik güncelleme mekanizmalarını manipüle ederek binlerce sisteme aynı anda sızabilirler. Kod bütünlüğü kadar, ağ üzerinden taşınan serileştirilmiş verilerin (*serialized data*) bütünlük denetimi yapılmadan geri çözülmesi (*deserialization*) de bu kategori altındaki en yıkıcı sistem ele geçirme zafiyetlerine zemin hazırlar.

---

## 🔍 Bütünlük Hatalarının Teknik Anatomisi

Yazılım ve veri bütünlüğü ihlalleri, genel olarak üç ana operasyonel katmanda gerçekleşir:

### 1. Güvensiz Nesne Serileştirmesi (Insecure Deserialization)
Programlama dillerinde nesneler, ağ üzerinden taşınmak veya diske kaydedilmek amacıyla metinsel veya ikili (*binary*) bir formata dönüştürülür (**Serialization**). Bu verinin tekrar nesneye dönüştürülmesi (**Deserialization**) esnasında, eğer verinin bütünlüğü kriptografik imzalarla doğrulanmıyorsa saldırgan veri paketinin içerisine sahte nesne sınıfları yerleştirir. Uygulama bu veriyi geri çözdüğü an, bellekte oluşan sahte nesnenin yıkıcı metotları (*destructors*) veya sihirli metotları (*magic methods*) tetiklenerek sunucu üzerinde doğrudan **Uzaktan Kod Çalıştırılmasına (RCE)** olanak tanır.

### 2. Yazılım Tedarik Zinciri Saldırıları (Supply Chain Attacks)
Yazılımcıların projelerinde kullandığı popüler açık kaynak kütüphanelerin depoları (*repository*) hedef alınır. Saldırganlar, kütüphane geliştiricisinin hesabını ele geçirerek veya kütüphane ismine çok benzer sahte paketler yayınlayarak (**Typosquatting** - *örneğin lodash yerine loadash*), zararlı kod barındıran paketleri yazılımcıların projelerine "meşru bağımlılık" olarak sızdırırlar. Yazılım derlendiğinde veya CI/CD süreçlerinden geçtiğinde, zararlı kodlar otomatik olarak üretim (*production*) ortamına taşınır.

### 3. Otomatik Güncelleme Mekanizmalarının Sabote Edilmesi
Birçok yazılım, belirli aralıklarla kendi sunucularına bağlanarak en güncel kod paketini indirir ve kurar. Eğer bu güncelleme paketleri sunucuda kriptografik bir özel anahtar (*Private Key*) ile imzalanmıyorsa ve istemci tarafında bu imza doğrulanmıyorsa, ağ arasına sızan bir saldırgan (**MitM**) sahte bir güncelleme paketi fırlatarak hedef cihazlarda yetkisiz kod yürütebilir.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code - Java Deserialization)
Aşağıdaki Java örneğinde, ağ üzerinden gelen kullanıcı oturum nesnesini geri çözen (*deserialize*) bir yapı yer almaktadır. Yazılımcı, gelen byte dizisinin bütünlüğünü ve kaynağını hiçbir şekilde doğrulamadan doğrudan nesneye dönüştürmektedir:

```java
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
 
public class VulnerableDeserializationServer {
    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Sunucu dinlemede...");
 
        while (true) {
            try (Socket socket = serverSocket.accept();
                 ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
                
                // GÜVENSİZ YAPI: Ağdan gelen ham byte verisi doğrudan deserialize ediliyor.
                // Gelen verinin bütünlüğü veya meşru bir istemciden gelip gelmediği doğrulanmıyor.
                Object obj = ois.readObject();
                System.out.println("Nesne başarıyla belleğe alındı.");
                
            } catch (Exception e) {
                System.out.println("Hata: " + e.getMessage());
            }
        }
    }
}
```
🎯 Saldırı Senaryosu
Saldırgan, sunucunun sınıf yolunda (classpath) yer alan ve bilinen bir zayıflığa sahip olan (örneğin Apache Commons Collections gibi eski kütüphaneler) sınıfları kullanarak özel bir zincirleme tetikleyici (gadget chain) hazırlar.

Bu zincirleme yapı, deserialize edildiğinde doğrudan Runtime.getRuntime().exec("rm -rf /") komutunu çalıştıracak şekilde yapılandırılmıştır.

Saldırgan bu zararlı byte dizisini sunucunun 8080 portuna gönderir.

ois.readObject() fonksiyonu çalıştırıldığı an, hiçbir güvenlik filtresine takılmadan işletim sistemi komutları saniyeler içinde yürütülür (RCE).

🔐 Doğru ve Güvenli Kod (Secure Code)
Nesne bütünlüğünü ve veri güvenliğini sağlamanın en kesin yolu, güvensiz serileştirme formatlarından (Java Native Serialization, PHP Serialize, Python Pickle vb.) tamamen kaçınmaktır.

Veri transferlerinde sadece yapılandırılmış ve davranışsal kod barındıramayan JSON veya Protocol Buffers (Protobuf) gibi güvenli formatlar tercih edilmelidir. Java gibi dillerde yerel deserialization kullanılmak zorundaysa, filtreleme listeleri (Look-Ahead Deserialization / ObjectInputFilter) uygulanmalıdır.
```java
Java
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class SecureDeserializationServer {
    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Güvenli sunucu dinlemede...");
 
        while (true) {
            try (Socket socket = serverSocket.accept();
                 ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
                
                // GÜVENLİ YAPI: Look-Ahead Deserialization filtresi tanımlanıyor.
                // Sadece açıkça izin verilen (beyaz listedeki) güvenli sınıfların çözülmesine izin verilir.
                // Saldırganın sunucuya göndereceği bilinmeyen zararlı gadget sınıfları anında reddedilir.
                ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                    "java.lang.*;com.company.models.UserSession;!*"
                );
                ois.setObjectInputFilter(filter);
                
                Object obj = ois.readObject();
                System.out.println("Doğrulanmış nesne güvenli bir şekilde belleğe alındı.");
                
            } catch (Exception e) {
                System.out.println("Güvenlik Engeli / Hata: " + e.getMessage());
            }
        }
    }
}
```
🧱 Savunma Katmanları (Defense-in-Depth)
Yazılım ve veri bütünlüğünü tüm süreç boyunca korumak amacıyla şu derinlemesine savunma ilkeleri entegre edilmelidir:

1. Yazılım Malzeme Listesi (SBOM) ve Bağımlılık Güvenliği
Geliştirilen uygulamaların içerisinde yer alan tüm harici kütüphanelerin ve bağımlılıkların sıkı bir takibi yapılmalıdır.

📊 SBOM (Software Bill of Materials): Uygulamanın kullandığı tüm üçüncü parti bileşenleri, kütüphaneleri ve bunların versiyonlarını listeleyen standartlaştırılmış bir yazılım malzeme listesi (SBOM) otomatik olarak üretilmelidir.

🔒 Bağımlılık Kilitleme (Dependency Locking): Paket yöneticilerinde (package-lock.json, Gemfile.lock, poetry.lock vb.) kütüphanelerin sadece versiyon numaraları değil, o paketlerin kriptografik bütünlük özetleri (SHA-256 hash değerleri) de kilitlenmelidir. Böylece, kütüphane deposu hacklense ve aynı versiyon numarasıyla zararlı bir paket yüklense bile, hash uyuşmazlığı nedeniyle CI/CD süreçleri derlemeyi otomatik olarak durduracaktır.

2. İki Faktörlü Paket Yönetimi ve İmzalı Güncelleme Paketleri
🔏 Kod İmzalama (Code Signing): Dağıtılan tüm yazılımlar, güncellemeler ve yürütülebilir dosyalar (executable), kurumun güvenli HSM (Hardware Security Module) cihazlarında saklanan özel anahtarlarıyla dijital olarak imzalanmalıdır. Alıcı istemci sistemler, bu paketleri kurmadan önce public key vasıtasıyla imzanın geçerliliğini doğrulamalıdır.

🛡️ Yayıncı Güvenliği: Paket yöneticilerindeki (npm, PyPI vb.) geliştirici hesaplarında Çok Faktörlü Kimlik Doğrulama (MFA) kullanımı zorunlu kılınmalıdır. Bu sayede, siber saldırganların geliştirici parolalarını ele geçirerek popüler paketlere zararlı güncellemeler çıkması engellenmiş olur.

3. Konteyner ve İmaj Güvenliği (CI/CD Pipeline Security)
Uygulamaların paketlendiği ve dağıtıldığı konteyner (Docker) dünyasında da bütünlük doğrulamaları kritik öneme sahiptir.

📦 Temel İmaj Güvenliği: Dockerfile içerisinde kullanılan taban imajlar (Base Images) bilinmeyen harici kaynaklardan çekilmemeli; sadece doğrulanmış yayıncıların (Official Images) imzalı imajları kullanılmalıdır.

🔍 İmaj Tarama ve İmzalama (Cosign / Docker Content Trust): Üretilen Docker imajları, kayıt defterine (Container Registry) gönderilmeden önce siber güvenlik açıklarına karşı otomatik olarak taranmalı (Trivy, Clair vb.) ve kriptografik olarak imzalanmalıdır (Cosign kullanımı ile). Kubernetes veya diğer konteyner orkestrasyon araçları, sadece bu doğrulanmış imzaya sahip imajları çalıştırmak üzere yapılandırılmalıdır.
# 🛡️ 3. Insecure Deserialization (Güvensiz Serileştirmeden Çıkarma)

Uygulamanın kullanıcı veya dış kaynaklardan aldığı serileştirilmiş (*Serialized*) nesne verilerini, kaynağını ve bütünlüğünü doğrulamadan geri çözümlemesi (*Deserialization*) sonucu ortaya çıkan ve doğrudan sistem hakimiyetinin kaybedilmesine yol açabilen kritik bir zafiyettir.

> 📦 **Serileştirme Nedir?** Programlama dillerinde serileştirme (*Serialization*), bellekteki canlı bir nesne yapısını (nesnenin öznitelikleri, durumları ve sınıf bilgileriyle birlikte) ağ üzerinden iletilebilecek veya diske kaydedilebilecek bir byte dizisine, XML veya JSON formatına dönüştürme işlemidir. Geri serileştirme (*Deserialization*) ise bu sürecin tam tersidir.

Zafiyet, sunucunun bu byte dizisini geri çözerek bellekte yeniden nesne oluştururken nesnenin kurucu (*constructor*), yıkıcı (*destructor*) veya dile özgü sihirli metotlarını (*magic methods*) kontrolsüz bir şekilde çalıştırmasından kaynaklanır. Saldırgan, serileştirilmiş verinin içerisine uygulamanın bağımlılıkları arasında yer alan meşru ancak tehlikeli sınıfları (**gadgets**) enjekte ederek sunucu üzerinde doğrudan **Uzaktan Kod Çalıştırılması (RCE)** elde edebilir.

---

## 🔍 Güvensiz Serileştirmenin Teknik Anatomisi

Insecure Deserialization saldırıları, standart bir girdi enjeksiyonundan farklı olarak doğrudan uygulamanın çalışma zamanı (*Runtime*) belleğine ve nesne haritasına yöneliktir. Süreç genellikle şu aşamalarla sömürülür:

*   🔮 **Sihirli Metotların Tetiklenmesi:** Programlama dillerinde bir nesne deserialize edilirken veya bellekten temizlenirken otomatik olarak çalışan özel metotlar bulunur (örneğin PHP'de `__wakeup()` ve `__destruct()`, Python'da `__reduce()`, Java'da `readObject()`). Saldırgan, byte dizisindeki sınıf yapılarını değiştirerek bu metotların içerisindeki iş mantığını kendi lehine manipüle eder.
*   🔗 **Gadget Zincirleri (Gadget Chains):** Uygulamanın veya projedeki harici kütüphanelerin içerisinde halihazırda var olan, tek başlarına zararsız ancak arka arkaya tetiklendiklerinde sistem komutları çalıştırabilen sınıflar dizisine **"Gadget"** denir. Saldırgan, serileştirilmiş nesnenin referanslarını bu gadget sınıflarını tetikleyecek şekilde yapılandırır. Nesne geri çözülürken bu zincirleme reaksiyon başlar ve sunucuda işletim sistemi komutu yürütülür.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code - Python Pickle)
Aşağıdaki Python örneğinde, bir web uygulamasının oturum bilgilerini saklamak ve geri okumak için Python'ın yerleşik ve son derece güvensiz olan `pickle` kütüphanesini kullandığı senaryo gösterilmektedir:

```python
import pickle
import base64
from flask import Flask, request, make_response
 
app = Flask(__name__)

# GÜVENSİZ YAPI: Kullanıcıdan tarayıcı çereziyle gelen serileştirilmiş veri 
# hiçbir doğrulama yapılmadan doğrudan pickle.loads() ile geri çözülüyor.
@app.route("/profile")
def view_profile():
    session_cookie = request.cookies.get("session")
    
    if not session_cookie:
        return "Lütfen giriş yapın.", 401
        
    try:
        # Base64 formatındaki çerez çözülüyor ve deserialize ediliyor
        serialized_data = base64.b64decode(session_cookie)
        user_session = pickle.loads(serialized_data)
        
        return f"Hoş geldiniz, {user_session.get('username')}"
    except Exception as e:
        return "Sistem hatası.", 500

if __name__ == "__main__":
    app.run()
🎯 Saldırı Senaryosu (RCE)
Saldırgan, Python'daki __reduce__ sihirli metodunu manipüle eden bir script yazar. Bu metot, nesne deserialize edilirken hangi fonksiyonun çalıştırılacağını belirler:

Python
import pickle
import base64
import os

class Exploit(object):
    def __reduce__(self):
        # Deserialization anında sunucu üzerinde tetiklenecek işletim sistemi komutu
        return (os.system, ("whoami",))
```
# Zararlı nesne serileştiriliyor ve base64 ile kodlanıyor
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print("Zararlı Çerez:", payload)
⚙️ Saldırı Nasıl Gerçekleşir?
Saldırgan yukarıdaki script ile ürettiği zararlı çerezi tarayıcısındaki session alanına yazar ve sayfayı yeniler.

Sunucu tarafında pickle.loads() fonksiyonu çalıştığı an, Exploit sınıfının __reduce__ metodu tetiklenir.

Sonuç: os.system("whoami") komutu sunucu işletim sisteminde doğrudan yürütülür ve komut çıktısı/sistem kontrolü saldırganın eline geçer.

🔐 Doğru ve Güvenli Kod (Secure Code)
Insecure Deserialization zafiyetini önlemenin en kesin ve birincil yöntemi, dış kaynaklardan gelen serileştirilmiş nesne verilerini kesinlikle kabul etmemektir.

Veri transferi ve durum saklama mimarilerinde nesne taşımak yerine, sadece düz veri öznitelikleri (Data Attributes) barındıran ve doğası gereği bünyesinde çalıştırılabilir kod taşıyamayan JSON veya XML (harici entity'leri kapalı şekilde) gibi güvenli standartlar tercih edilmelidir.
```python
Python
import json
import base64
from flask import Flask, request, jsonify
 
app = Flask(__name__)

# GÜVENLİ YAPI: Durum yönetimi için nesne serileştirme yerine JSON formatı kullanılıyor.
# JSON sadece saf metin verisi taşır, bellekte güvensiz nesne metotlarını tetikleyemez.
@app.route("/profile")
def view_profile():
    session_cookie = request.cookies.get("session")
    
    if not session_cookie:
        return "Lütfen giriş yapın.", 401
        
    try:
        # Base64 ile kodlanmış JSON verisi çözülüyor
        decoded_data = base64.b64decode(session_cookie).decode('utf-8')
        
        # Güvenli bir şekilde yalnızca veri sözlüğü geri yükleniyor
        user_session = json.loads(decoded_data)
        
        # Girdinin tipi ve beklenen alanların varlığı doğrulanıyor
        if not isinstance(user_session, dict) or "username" not in user_session:
            return "Geçersiz oturum verisi.", 400
            
        return f"Hoş geldiniz, {user_session['username']}"
    except Exception:
        return "Bir hata oluştu.", 500

if __name__ == "__main__":
    app.run()
```
🧱 Savunma Katmanları (Defense-in-Depth)
Eğer sistem mimarisinde yerel serileştirme (Native Deserialization) protokollerinin kullanımı teknik olarak zorunlu ise, güvenliği pekiştirmek amacıyla şu derinlemesine savunma önlemleri entegre edilmelidir:

1. Sıkı Beyaz Liste (Whitelisting) Tabanlı Sınıf Filtreleme
Geri serileştirme işlemini gerçekleştiren fonksiyonun, sistemdeki tüm sınıfları (Classes) çözmesine izin verilmemelidir.

🔍 Look-Ahead Deserialization: Nesne belleğe tamamen yüklenip metotları tetiklenmeden önce, hangi sınıf tipine ait olduğu henüz byte dizisi aşamasındayken analiz edilmelidir.

🛡️ Sınıf Sınırlandırması: Yalnızca açıkça izin verilmiş, iş mantığı açısından meşru olan veri modellerinin çözülmesine izin verilmeli; bunun dışındaki tüm bilinmeyen veya harici kütüphane sınıfları (gadget'lar) daha çözümleme başlamadan reddedilmelidir.

2. Bağımlılıkları ve "Gadget" Barındıran Kütüphaneleri Güncel Tutmak
Saldırganlar, nesne deserialize ederken komut çalıştırabilmek için sistemdeki mevcut kütüphanelerin açıklarından (gadget'lardan) faydalanırlar.

🔄 Düzenli Tarama: Projede kullanılan tüm harici kütüphaneler (örneğin Java için Apache Commons Collections, Spring Core vb.) düzenli olarak taranmalı ve bilinen "gadget zinciri" açıklarına (CVE kayıtlarına) sahip olan eski sürümler en güncel versiyonlarına yükseltilmelidir.

❌ Zinciri Kırmak: Kütüphaneler güncellendiğinde, sisteme zararlı bir nesne enjekte edilse dahi, nesnenin sömürü gerçekleştirmek için ihtiyaç duyacağı zayıf sınıflar sistemde bulunamayacağı için saldırı başarısız olur.

3. Kısıtlı Yetki ve Uygulama İzolasyonu (Sandboxing)
Olası bir deserialization sömürüsünün sistem geneline yayılmasını engellemek amacıyla sunucu tarafında sıkı izolasyon önlemleri alınmalıdır.

👤 En Az Yetki İlkesi: Geri serileştirme işlemlerini yürüten uygulama süreci, işletim sisteminde root veya yönetici yetkilerine sahip olmayan, son derece kısıtlı bir sistem kullanıcısı adıyla çalıştırılmalıdır.

🐳 Konteynerizasyon: Uygulama, işletim sisteminin diğer kritik dizinlerine erişemeyecek şekilde Docker konteynerleri veya izole edilmiş sanal sandbox ortamlarında barındırılmalıdır. Bu sayede saldırgan RCE elde etse bile, yalnızca izole edilmiş boş bir hücrenin içinde kalır; ana sunucuya veya veri tabanlarına zarar veremez.
# 🛡️ 4. Sensitive Data Exposure & Information Disclosure

Uygulamanın şifreleme mekanizmalarındaki yetersizlikler, zayıf altyapı konfigürasyonları, kontrolsüz hata yönetimi (*exception handling*) veya aşırı bilgi sızdıran API yanıtları nedeniyle; kullanıcı şifreleri, kredi kartları, kişisel veriler (KVKK/GDPR kapsamındaki veriler) veya sistemin teknik altyapısına dair gizli bilgilerin (API anahtarları, veri tabanı şemaları, sunucu yolları vb.) yetkisiz kişilerin eline geçmesiyle sonuçlanan geniş kapsamlı siber güvenlik zafiyetleri kategorisidir.

Bu kategori, OWASP listelerinde genellikle iki ayrı kavramın birleşimi olarak ele alınır:

*   🔒 **Sensitive Data Exposure:** Finansal, tıbbi veya kişisel verilerin depolanırken ya da ağ üzerinde taşınırken zayıf kriptografik algoritmalarla (veya tamamen şifresiz) korunması durumudur.
*   📢 **Information Disclosure:** Uygulamanın ürettiği hata mesajları, yorum satırları veya sistem logları aracılığıyla saldırganlara altyapı mimarisi, kullanılan kütüphane versiyonları ya da kod dizini hakkında teknik ipuçları vermesidir.

---

## 🔍 Veri İfşası ve Bilgi Sızıntılarının Teknik Anatomisi

Saldırganlar, hassas verileri ele geçirmek veya sistem hakkında keşif yapmak için şu zayıflıklardan yararlanırlar:

*   📖 **Açık Metin (Cleartext) İletişim ve Depolama:** Hassas verilerin (parolalar, API anahtarları) veri tabanında MD5, SHA-1 gibi kırılmış algoritmalarla veya doğrudan düz metin olarak saklanması; ağ üzerinde HTTPS yerine düz HTTP protokolünün kullanılması.
*   ⚠️ **Kontrolsüz Hata Mesajları (Detailed Stack Traces):** Veri tabanı sorgu hatalarında veya sistem istisnalarında (*Exceptions*), sunucunun tarayıcı ekranına ham hata detaylarını basması. Bu mesajlar genellikle SQL sorgularının yapısını, tablo isimlerini, kullanılan framework versiyonlarını ve sunucunun yerel dosya yollarını ifşa eder.
*   📥 **Gereksiz API Yanıt Gövdeleri (Over-fetching):** API uç noktalarının, istemcinin arayüzde (UI) göstermek için ihtiyaç duyduğu veriden çok daha fazlasını JSON yanıtında döndürmesi. Örneğin, arayüzde sadece kullanıcının adını göstermek gerekirken API'nin tüm kullanıcı nesnesini (`{"id": 1, "name": "Ahmet", "password_hash": "...", "ssn": "..."}`) istemciye fırlatması.

---

## 💻 Kod Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code - Node.js / Express)
Aşağıdaki Express.js örneğinde, bir kullanıcının profil bilgilerini getiren ve olası hataları doğrudan istemciye dönen güvensiz bir API yapısı yer almaktadır:

```javascript
const express = require('express');
const app = express();
const db = require('./dbConnection'); // Veri tabanı modülü

// GÜVENSİZ YAPI: API yanıtında tüm veri tabanı satırı (şifre hashi dahil) istemciye fırlatılıyor.
// Ayrıca hata oluştuğunda ham sistem hatası (Stack Trace) doğrudan ekrana basılıyor.
app.get('/api/user/:id', async (req, res) => {
    try {
        const userId = req.params.id;
        const query = `SELECT * FROM users WHERE id = ${userId}`; // SQLi riskine de açık
        const user = await db.query(query);
        
        // GÜVENSİZ: select * ile çekilen password_hash ve ssn (TCKN) gibi hassas alanlar filtrelenmeden dönülüyor
        return res.status(200).json(user);
    } catch (error) {
        // GÜVENSİZ: Tüm sistem hata detayı, veri tabanı şeması ve kod yolları saldırgana ifşa ediliyor
        return res.status(500).json({ 
            success: false, 
            error: error.message, 
            stack: error.stack 
        });
    }
});
 
app.listen(3000);
```
🎯 Saldırı ve Sızıntı Senaryosu
Over-fetching (Aşırı Veri Sızıntısı): Meşru bir istemci /api/user/12 isteği attığında, tarayıcı ekranında sadece isim gösterilse bile arka plandaki JSON yanıtında kullanıcının şifrelenmiş parola hash değeri (password_hash) ve kimlik numarası (ssn) açıkça sızdırılmış olur.

Stack Trace İfşası: Saldırgan parametreyi /api/user/gecersiz_id şeklinde manipüle ettiğinde sorgu patlar ve sunucu saldırgana şu yanıtı döner:
```json
JSON
{
  "success": false,
  "error": "Table 'my_app_db.users' doesn't exist",
  "stack": "Error: Table 'my_app_db.users' doesn't exist\n    at Connection.query (/var/www/app/node_modules/mysql/lib/Connection.js:150:11)\n    at /var/www/app/server.js:10:30"
}
Sonuç: Saldırgan bu hata sayesinde veri tabanı ismini (my_app_db), tablo ismini (users), kullanılan sürücüyü (mysql) ve sunucudaki projenin mutlak yolunu (/var/www/app/) kesin olarak öğrenir ve bir sonraki saldırı adımını bu bilgilere göre şekillendirir.

🔐 Doğru ve Güvenli Kod (Secure Code)
Hassas veri ifşasını önlemek için API yanıtlarında sadece ihtiyaç duyulan veri alanları (Data Projection / DTO) istemciye aktarılmalı, veri tabanındaki hassas veriler kriptografik olarak maskelenmeli ve tüm hatalar merkezi bir yapıda jenerik mesajlara dönüştürülmelidir.
```
```javascript
JavaScript
const express = require('express');
const app = express();
const db = require('./dbConnection');

// GÜVENLİ YAPI: Sadece izin verilen güvenli alanlar sorgulanıyor ve DTO mantığıyla dönülüyor
app.get('/api/user/:id', async (req, res) => {
    try {
        const userId = parseInt(req.params.id, 10);
        if (isNaN(userId)) {
            return res.status(400).json({ success: false, message: "Geçersiz parametre." });
        }
        
        // GÜVENLİ: Sadece arayüzün ihtiyaç duyduğu isim ve e-posta alanları seçiliyor (Projection)
        // Hassas kimlik ve şifre verileri veri tabanından hiç çekilmiyor
        const query = 'SELECT id, username, email FROM users WHERE id = ?';
        const [user] = await db.query(query, [userId]);
        
        if (!user) {
            return res.status(404).json({ success: false, message: "Kullanıcı bulunamadı." });
        }
        
        return res.status(200).json({ success: true, data: user });
    } catch (error) {
        // GÜVENLİ: Hata detayları sunucu tarafında güvenli log sistemine (Winston vb.) kaydedilir
        // logSystem.error(error.stack);
        
        // Dış dünyaya sadece jenerik ve temiz bir hata mesajı dönülür
        return res.status(500).json({ 
            success: false, 
            message: "Sistemde bir hata oluştu. Lütfen daha sonra tekrar deneyin." 
        });
    }
});
 
app.listen(3000);
```
🧱 Savunma Katmanları (Defense-in-Depth)
Sistem mimarisindeki veri sızıntılarını en aza indirmek amacıyla şu ek derinlemesine savunma katmanları uygulanmalıdır:

1. Merkezi Hata Yönetimi (Global Exception Handling)
Hata yönetimi kod sayfalarında manuel ve dağınık olarak yapılmamalıdır. Bir geliştiricinin hata yakalamayı (try-catch) unutması durumunda, web sunucusu (Express, IIS, Tomcat) varsayılan olarak tüm stack trace detayını tarayıcıya basabilir.

⚙️ Global Middleware: Uygulama mimarisinde tüm hataları yakalayan merkezi bir ara katman (Global Error Handling Middleware) tanımlanmalıdır.

📁 Log Dosyaları: Bu merkezi katman, yakaladığı ham teknik hataları sunucu tarafındaki güvenli diske (Log Files) yazmalı; istemci tarafına fırlatılan yanıtları ise her zaman standardı belirlenmiş jenerik hata şablonlarına (örneğin HTTP 500 kodu ve sabit bir hata mesajı) dönüştürmelidir.

2. Önbellekleme ve Tarayıcı Güvenliği (Cache Control)
Ağ üzerindeki trafiğin veya yerel bilgisayarların önbelleklerinin (cache) sömürülmesiyle hassas verilerin sızması engellenmelidir.

🔒 Güvenlik Başlıkları: Hassas veri barındıran API ve web sayfalarında, tarayıcıların ve aradaki proxy sunucularının bu verileri diske kaydetmesini önlemek amacıyla şu HTTP başlıkları (Headers) zorunlu olarak gönderilmelidir:

HTTP
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
Expires: 0
⏱️ Önbellek İzolasyonu: Bu sayede, ortak kullanılan bilgisayarlarda kullanıcı çıkış yaptıktan sonra "Geri" butonuna basılsa dahi eski tarayıcı önbelleğindeki hassas sayfalar veya kişisel veriler ekrana gelmeyecektir.

3. Hassas Verileri Maskeleme ve Sınırlandırma (Data Masking)
Verilerin veri tabanında, log dosyalarında veya ekranlarda meşru kullanıcılar tarafından dahi gereksiz yere tam olarak görülmesi engellenmelidir.

📝 Log Maskeleme (Log Masking): Log dosyalarına (application logs) yazılan veriler otomatik bir filtreden geçirilmeli; kredi kartı numaraları, şifreler veya kimlik bilgileri loglara yazılmadan önce regex yardımıyla maskelenmelidir (4543-XXXX-XXXX-1234 vb.).

🛡️ Veri Maskeleme (Data Masking): Veri tabanından veri çeken servis katmanlarında, rol tabanlı veri maskeleme kuralları işletilmelidir. Müşteri temsilcisinin ekranında kredi kartının sadece son 4 hanesi gösterilmeli; verinin tamamı sadece şifreli ödeme katmanı (PCI-DSS uyumlu alan) tarafından işlenebilmelidir.

# 🛡️ 5. Clickjacking (UI Redressing)

Saldırganın, görsel ve arayüzsel hileler kullanarak, kullanıcının güvendiği meşru bir web sitesini (örneğin bir sosyal medya hesabı, e-ticaret paneli veya bankacılık ekranı) kendi hazırladığı zararlı bir sayfanın içerisine görünmez bir katman (`iframe`) olarak gömmesi ve kullanıcıyı farkında olmadan bu gizli arayüzdeki butonlara tıklamaya zorlamasıyla gerçekleşen saldırı türüne **Clickjacking (Kullanıcı Arayüzü Maskeleme / UI Redressing)** denir.

> 🪟 **Iframe İstismarı:** Bu zafiyet, web tarayıcılarının sayfaları iç içe çerçeveler halinde (`<iframe>`, `<frame>`, `<object>` veya `<embed>`) görüntüleme yeteneğini suistimal eder. 

Saldırgan, kullanıcının tıklamak isteyeceği cazip bir oyun, hediye butonu veya "Tıkla ve Ödül Kazan" sayfası tasarlar. Bu sayfanın tam üzerine, hedef aldığı meşru web sitesini yerleştirir ancak CSS kullanarak bu üst katmanın şeffaflığını tamamen sıfırlar (`opacity: 0`). Kullanıcı alt taraftaki sahte butona tıkladığını sanırken, aslında üstte duran görünmez meşru sitenin "Hesabımı Sil", "Para Gönder" veya "Takip Et" gibi kritik bir butonuna tıklamış olur.

---

## 🔍 Clickjacking Saldırılarının Teknik Anatomisi

Clickjacking saldırıları, tamamen istemci tarafında (*Client-Side*) gerçekleşen ve tarayıcı davranışlarını hedef alan bir manipülasyondur. Saldırı genellikle şu aşamalardan oluşur:

*   🔍 **Zafiyet Tespiti:** Saldırgan, hedef web sitesinin HTTP yanıt başlıklarını (*Headers*) inceleyerek, sitenin başka bir platformda `<iframe>` içerisine gömülmesini engelleyen güvenlik politikalarının (`X-Frame-Options` veya CSP `frame-ancestors`) eksik olup olmadığını kontrol eder.
*   📐 **Görsel Hizalama (CSS Layering):** Saldırgan, kendi zararlı HTML sayfasında CSS `z-index` özelliğini kullanarak iki farklı katman oluşturur. Alt katmana (kurbanın göreceği meşru katman) ilgi çekici bir görsel yerleştirir. Üst katmana ise kurbanın meşru oturumunun açık olduğu hedef siteyi `<iframe>` olarak gömer.
*   👻 **Şeffaflık Manipülasyonu:** Üstteki iframe katmanının CSS `opacity` değeri `0` (veya sıfıra çok yakın) yapılarak tamamen görünmez hale getirilir. CSS `pointer-events` ayarlarıyla tıklama hareketlerinin görünmez siteye ulaşması sağlanır. Kurban fareyi tıklattığı an, tarayıcı bu tıklamayı en üstteki görünmez katmanda yer alan aktif butona iletir.

---

## 💻 Kod ve Yapılandırma Örnekleri

### ❌ Hatalı ve Savunmasız Kod (Vulnerable Code - Attacker's HTML Exploit)
Aşağıdaki HTML örneğinde, bir saldırganın kurbanı kandırmak amacıyla hazırladığı ve hedef sitenin (`targetapp.com`) güvenlik önlemlerinin olmamasından faydalanarak tasarladığı bir clickjacking sömürü sayfası yer almaktadır:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Bedava Ödül Kazan!</title>
    <style>
        /* Saldırganın kurbana gösterdiği yem katman */
        .decoy-container {
            position: absolute;
            top: 100px;
            left: 100px;
            z-index: 1; /* Altta kalacak katman */
        }
        
        .decoy-button {
            background-color: #ff4757;
            color: white;
            padding: 15px 32px;
            font-size: 18px;
            border: none;
            cursor: pointer;
        }
 
        /* Üste binen görünmez meşru hedef site katmanı (iframe) */
        .victim-iframe {
            position: absolute;
            top: 80px;  /* Butonların üst üste gelmesi için tam hizalama yapılır */
            left: 90px;
            width: 500px;
            height: 300px;
            z-index: 2; /* Üstte kalacak katman */
            opacity: 0.0; /* IFRAME'I TAMAMEN GÖRÜNMEZ YAPAR */
            filter: alpha(opacity=0); /* Eski tarayıcılar için */
        }
    </style>
</head>
<body>
 
    <!-- Kurban sadece bu kırmızı butonu görür -->
    <div class="decoy-container">
        <h2>Tebrikler! 1000 TL Hediye Çeki Kazandınız!</h2>
        <button class="decoy-button">Ödülü Almak İçin Tıkla!</button>
    </div>
 
    <!-- Kurbanın ruhu duymadan arka planda duran asıl hedef site -->
    <!-- Kullanıcı butona bastığında, aslında hedef sitenin "Hesabımı Kapat" butonuna tıklar -->
    <iframe class="victim-iframe" src="[http://targetapp.com/settings/delete-account](http://targetapp.com/settings/delete-account)"></iframe>
</body>
</html>
```
🔐 Doğru ve Güvenli Yapılandırma (Secure Server Headers)
Clickjacking saldırılarını önlemenin en kesin yöntemi, web uygulamasının tarayıcılar tarafından başka bir sitenin içerisine gömülmesini (embed/iframe) sunucu seviyesinde göndereceğimiz HTTP güvenlik başlıklarıyla kesin olarak yasaklamaktır.

1. Modern Güvenlik Bariyeri: Content Security Policy (CSP) frame-ancestors
Modern tarayıcılarda clickjacking koruması için en esnek ve güçlü yöntem CSP içerisinde yer alan frame-ancestors direktifidir.

Nginx
# Nginx Sunucu Yapılandırması (GÜVENLİ)
# Sitenin hiçbir harici platformda iframe olarak gömülmesine izin verilmez (Kendi domaini dahil)
add_header Content-Security-Policy "frame-ancestors 'none';" always;

# Alternatif A: Sitenin sadece kendi alan adı altındaki sayfalar tarafından gömülmesine izin verilir
# add_header Content-Security-Policy "frame-ancestors 'self';" always;

# Alternatif B: Sadece güvenilen belirli bir domainin gömmesine izin verilir
# add_header Content-Security-Policy "frame-ancestors 'self' trusted-partner.com;" always;
2. Geleneksel Güvenlik Bariyeri: X-Frame-Options (XFO)
Eski tarayıcıları da kapsayan geriye dönük uyumluluk sağlamak amacıyla CSP ile birlikte X-Frame-Options başlığının da gönderilmesi tavsiye edilir.

Nginx
# Nginx Sunucu Yapılandırması (GÜVENLİ)
# Tarayıcıya sitenin hiçbir koşulda iframe içerisine alınamayacağını söyler
add_header X-Frame-Options "DENY" always;

# Alternatif: Yalnızca sitenin kendi sayfaları içerisinde çerçevelenmesine izin verir
# add_header X-Frame-Options "SAMEORIGIN" always;
🧱 Savunma Katmanları (Defense-in-Depth)
HTTP başlıklarının yanı sıra, clickjacking risklerinin ve olası bypass yöntemlerinin önüne geçmek amacıyla şu ek savunma katmanları uygulanmalıdır:

1. SameSite Çerez Bayrağı Yapılandırması (SameSite Cookies)
Clickjacking saldırılarının başarıya ulaşması için, kurbanın görünmez iframe içerisinde gömülen hedef sitede aktif bir oturumunun (Session) bulunması gerekir.

🍪 Çapraz İstek Kısıtlaması: Oturum çerezleri SameSite=Lax veya SameSite=Strict olarak yapılandırıldığında, tarayıcı bu çerezleri üçüncü parti siteler üzerinden yapılan çapraz kaynak (cross-site) isteklerinde veya iframe çerçevelerinde sunucuye göndermez.

🚫 Oturum Engelleme: Bu durumda, kurban saldırganın sayfasına girdiğinde iframe içerisindeki hedef site açılsa bile kullanıcı oturumu aktif olmayacağı (giriş yapılmamış gibi görüneceği) için, saldırganın görünmez butonlar vasıtasıyla yetkilendirilmiş işlemler tetiklemesi engellenmiş olur.

2. Kritik İşlemlerde Yeniden Doğrulama ve Ekstra Onay Adımları
Para transferi, şifre değiştirme veya hesap silme gibi geri dönüşü olmayan yüksek riskli işlemler sadece basit bir tıklama eylemine dayandırılmamalıdır.

🔐 Ek Doğrulama: Kritik butonlara tıklatılmadan önce kullanıcıdan mevcut parolasını tekrar girmesi istenmeli, iki faktörlü doğrulama (2FA) kodu talep edilmeli veya dinamik CAPTCHA testleri devreye sokulmalıdır.

⚡ Akış Kesintisi: Saldırgan sayfayı görünmez bir şekilde gömmeyi başarsa bile, kurbanın o an klavyeden gireceği dinamik şifreyi veya doğrulama kodunu tahmin edemeyeceği için saldırı yürütme (execution) aşamasında kesintiye uğrar.

3. Frame-Busting (JavaScript Korunması) ve Kısıtlamaları
HTTP başlıklarının (CSP/XFO) teknik veya sistemsel sebeplerle kullanılamadığı çok eski legacy ortamlarda, istemci tarafında çalışan JavaScript tabanlı koruma kodları (Frame-Busting) son çare olarak kullanılabilir.
```javascript
JavaScript
// Geleneksel Frame-Busting Script Örneği
if (self !== top) {
    // Eğer mevcut pencere en üst pencere değilse (yani bir iframe içindeyse)
    // Tarayıcıyı doğrudan kendi orijinal adresine yönlendirerek çerçeveyi kırar
    top.location = self.location;
}```
⚠️ Önemli Uyarı: JavaScript tabanlı korumalar (Frame-Busting) siber güvenlikte tek başına kesin bir koruma yöntemi sayılmaz. Saldırganlar, iframe etiketine ekleyecekleri HTML5 sandbox özniteliğiyle (özellikle allow-top-navigation iznini vermeyerek) tarayıcının üst seviye yönlendirmeler yapmasını bloke edebilir ve bu JavaScript korumasını kolayca bypass edebilirler. Bu nedenle asıl savunma her zaman sunucu seviyesindeki CSP ve X-Frame-Options yapılandırmaları olmalıdır.
