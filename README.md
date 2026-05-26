# McShield Obfuscator 1.0

> Obfuscator Java dành riêng cho plugin Minecraft/Paper/Bukkit.  
> Mục tiêu của McShield là **tăng độ khó khi decompile**, **che main/plugin entry**, **làm rối class/method/string**, nhưng vẫn ưu tiên plugin sau obf phải load được trên server.

---

## Giới thiệu

**McShield Obfuscator 1.0** là công cụ obfuscate `.jar` dành cho plugin Minecraft.

McShield tập trung vào các vấn đề thường gặp khi obf plugin Bukkit/Paper:

- Không làm lỗi `onEnable`, `onDisable`, `onCommand`.
- Không phá enum, `EnumMap`, `EnumSet`.
- Không rename bừa API public nếu plugin có API.
- Che class main bằng cơ chế `boot.Pivot`.
- Tách main thật khỏi superclass-chain dễ dò.
- Tạo decoy class để gây nhiễu khi scan `JavaPlugin`.
- Có config riêng cho plugin thường và plugin có API.

---

## Lưu ý quan trọng

McShield **không cam kết plugin không thể bị reverse 100%**.

Obfuscation chỉ giúp:

- tăng chi phí phân tích;
- làm code decompile khó đọc hơn;
- chống scan main đơn giản;
- che bớt string/logic nhạy cảm;
- làm người crack tốn thời gian hơn.

Nếu plugin chạy trên JVM thì về lý thuyết vẫn có thể bị phân tích.  
Mục tiêu thực tế của McShield là: **khó hơn, rối hơn, nhưng vẫn chạy ổn định**.

---

## Tính năng chính

### Minecraft-safe obfuscation

- Giữ `plugin.yml` hợp lệ.
- Tự cập nhật `main` trong `plugin.yml`.
- Giữ các lifecycle method quan trọng:
  - `onLoad`
  - `onEnable`
  - `onDisable`
  - `onCommand`
  - `onTabComplete`
- Không đổi command key mặc định để tránh lỗi `getCommand(...)`.

### Decoy system

McShield có thể tạo:

- JavaPlugin decoy.
- Delegate decoy.
- Class/method/field rác.
- Resource decoy.
- Fake C metadata.

Mục tiêu là làm nhiễu các script kiểu:

```text
tìm class nào extends JavaPlugin
tìm class nào có onEnable
tìm class nào có checkLicense
tìm class nào có nhiều getter manager
```

### String protection target-only

McShield không bật global string encryption mặc định, vì một số thư viện shaded như HTTP/OkHttp/Apache rất dễ lỗi verifier nếu bị rewrite bytecode quá mạnh.

Thay vào đó McShield ưu tiên:

```text
mã hóa string target trong delegate/main plugin
bỏ qua dependency nhạy cảm
giữ frame mode preserve
```

### Native Guard tùy chọn

McShield có hỗ trợ native guard tùy chọn.

Mặc định config public để `nativeGuard.enabled: false` nhằm tương thích nhiều host/panel hơn.

---

## Cài đặt

Yêu cầu:

- Java 17 trở lên.
- Plugin đầu vào dạng `.jar`.
- Thư mục lib nếu plugin cần dependency ngoài.

Clone repo:

```bash
git clone https://github.com/yourname/mcshield-obfuscator.git
cd mcshield-obfuscator
```

Build:

```bash
./build.sh
```

Hoặc dùng jar release:

```bash
java -jar mcshield-1.0.jar --help
```

---

## Cách dùng

Plugin bình thường:

```bash
java -jar mcshield-1.0.jar input.jar output-obf.jar -config config/mcshield-1.0-normal.yml -lib ./libs
```

Plugin có API public:

```bash
java -jar mcshield-1.0.jar input.jar output-obf.jar -config config/mcshield-1.0-api.yml -lib ./libs
```

Ví dụ:

```bash
java -jar mcshield-1.0.jar MyPlugin.jar MyPlugin-obf.jar -config config/mcshield-1.0-normal.yml
```

---

## Config có sẵn

### `mcshield-1.0-normal.yml`

Dành cho plugin bình thường.

Phù hợp khi:

- plugin không có API public lớn;
- muốn obf class/method/field ở mức an toàn;
- muốn che main tốt;
- muốn có decoy vừa phải;
- ưu tiên plugin load ổn.

### `mcshield-1.0-api.yml`

Dành cho plugin có API.

Phù hợp khi:

- plugin khác hook vào API của bạn;
- cần giữ public method/field ổn định;
- không muốn lỗi `NoSuchMethodError`;
- muốn obf class/main nhưng không phá binary compatibility.

---

## Ví dụ trước khi obf

Code plugin ban đầu:

```java
package me.example.payment;

import org.bukkit.plugin.java.JavaPlugin;

public final class PaymentPlugin extends JavaPlugin {
    private LicenseManager licenseManager;
    private PaymentManager paymentManager;

    @Override
    public void onEnable() {
        saveDefaultConfig();

        this.licenseManager = new LicenseManager(this);
        this.paymentManager = new PaymentManager(this);

        if (!licenseManager.checkLicense()) {
            getLogger().warning("License invalid!");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        getCommand("pay").setExecutor(new PayCommand(this));
        getCommand("payadmin").setExecutor(new PayAdminCommand(this));

        getLogger().info("PaymentPlugin enabled!");
    }

    @Override
    public void onDisable() {
        getLogger().info("PaymentPlugin disabled!");
    }

    public PaymentManager getPaymentManager() {
        return paymentManager;
    }

    public LicenseManager getLicenseManager() {
        return licenseManager;
    }
}
```

`plugin.yml` ban đầu:

```yaml
name: PaymentPlugin
version: 1.0.0
main: me.example.payment.PaymentPlugin
api-version: 1.20
commands:
  pay:
    description: User payment command
    usage: /pay
  payadmin:
    description: Admin payment command
    usage: /payadmin
```

---

## Ví dụ sau khi obf

Sau khi chạy McShield, `plugin.yml` sẽ không còn trỏ vào class logic thật:

```yaml
name: PaymentPlugin
version: 1.0.0
main: boot.Pivot
api-version: 1.20
commands:
  pay:
    description: User payment command
    usage: /pay
  payadmin:
    description: Admin payment command
    usage: /payadmin
```

Khi decompile, main entry chỉ còn là shell:

```java
package boot;

import org.bukkit.plugin.java.JavaPlugin;

public final class Pivot extends JavaPlugin {
    private Object a;
    private int b;

    public void onEnable() {
        x1();
    }

    public void onDisable() {
        x2();
    }

    public boolean onCommand(...) {
        return x3(...);
    }
}
```

Class logic thật không còn nằm trên đường:

```text
plugin.yml -> main -> superclass chain -> real plugin
```

Mà sẽ thành dạng:

```text
plugin.yml
  -> boot.Pivot
      -> shell dispatch
          -> delegate đã rename/obf
          -> decoy swarm gây nhiễu
```

Ví dụ decompile class delegate có thể thành:

```java
package z;

public class rqqmhlxuqtnvazpkuwyjdrsq {
    private Object a;
    private Object b;
    private Object c;
    private boolean d;

    public void mf1c5a961() {
        // code đã bị rename, string target đã được mã hóa,
        // nhiều class decoy có surface giống nhau để gây nhiễu.
    }

    public Object getPaymentManager() {
        return b;
    }
}
```

Ngoài ra trong JAR còn có nhiều class decoy kiểu:

```text
z/a8dkwjskd...
z/bxpqkqll...
z/rqoeuzmx...
boot/Pivot.class
META-INF/.mcshield/...
```

Điều này làm các cách scan đơn giản khó hơn:

```text
scan class extends JavaPlugin
scan class có onEnable
scan class có checkLicense
scan class có nhiều getter manager
```

---

## Vì sao không obf toàn bộ plugin.yml?

Bukkit/Paper cần đọc `plugin.yml` **trước khi plugin chạy**.

Nếu mã hóa hoặc xóa hoàn toàn `plugin.yml`, server sẽ không biết:

```text
plugin tên gì
main class là gì
api-version là gì
command nào cần đăng ký
dependency nào cần load trước
```

Vì vậy McShield giữ `plugin.yml` hợp lệ.  
Mặc định McShield **không rename command key** để tránh lỗi:

```text
Unknown command
getCommand(...) trả null
usage hiện command rác
```

Nếu bạn muốn che command, hãy tự test kỹ trước khi release.

---

## Khuyến nghị khi dùng

Nên:

- Build từ JAR gốc sạch.
- Không obf chồng lên output cũ.
- Test trên server local trước.
- Giữ `mapping.writeFile: false` khi release.
- Dùng config API nếu plugin có API public.
- Giữ `frames.mode: preserve` cho plugin có dependency phức tạp.

Không nên:

- Bật global string encryption cho mọi class.
- Obf dependency HTTP/OkHttp/Apache quá mạnh.
- Rename public API nếu plugin khác hook vào.
- Strip command khỏi plugin.yml nếu plugin dùng `getCommand(...)`.
- Quảng cáo là “uncrackable”.

---

## Lỗi thường gặp

### Plugin báo `VerifyError`

Nguyên nhân thường gặp:

```text
bytecode transformer đụng StackMapTable
dependency shaded bị rewrite quá mạnh
frames compute sai hierarchy
```

Cách xử lý:

```yaml
frames:
  mode: preserve

stringEncryption:
  enabled: false

controlFlow:
  enabled: false
```

### Lỗi `NoSuchMethodError`

Thường do rename public method/API.

Cách xử lý:

```yaml
renaming:
  keepNonPrivateMethods: true
```

Hoặc dùng:

```text
config/mcshield-1.0-api.yml
```

### Command không chạy

Không rename hoặc strip command key trong `plugin.yml`.

```yaml
minecraft:
  commandRename:
    enabled: false
  stripCommands: false
```

### EnumMap bị lỗi

Bật enum safe:

```yaml
renaming:
  enumSafe: true
```

---

## Open-source note

McShield là community obfuscator cho Minecraft plugin.  
Source public giúp mọi người học và bảo vệ plugin tốt hơn, nhưng cũng có nghĩa là output không nên được xem là bảo mật tuyệt đối.

Mỗi project nên có config riêng.  
Mỗi build nên dùng seed khác nhau.

---

## License

Bạn có thể chọn license phù hợp cho repo, ví dụ:

```text
MIT License
Apache-2.0
GPL-3.0
```

Nếu muốn cộng đồng dùng rộng rãi, MIT hoặc Apache-2.0 là dễ nhất.

---

## Credits

McShield được tạo để hỗ trợ cộng đồng developer Minecraft plugin Việt Nam có thêm một công cụ obfuscate dễ dùng, an toàn và tùy chỉnh được.

Made with ❤️ for Minecraft plugin developers.
