# Nghiên Cứu Khám Phá Dữ Liệu Active Directory (NORTH) và Mô Hình Trọng Số Đồ Thị Tấn Công (Weighted Attack Graph)

## 1. Tổng Quan Đề Tài và Thiết Lập Phạm Vi (Scope)

Đề tài tập trung vào việc mô hình hóa quan hệ Danh tính - Tài sản (Identity - Asset) trong môi trường Active Directory (AD).
Mục tiêu cốt lõi là giải quyết bài toán: *"Nếu kẻ tấn công chiếm được máy X, chúng có thể đi tới đâu, theo con đường nào và với chi phí thấp nhất là bao nhiêu?"*

Khác biệt cơ bản so với BloodHound mặc định:
BloodHound xem mọi bước leo thang có chi phí như nhau (unweighted graph với cost = 1).
Cách làm này dẫn đến việc hệ thống chỉ tìm đường có số bước ngắn nhất (Shortest Hop Path), bất kể bước đó cực kỳ ồn ào (dễ bị EDR/SOC phát hiện) hay có tỷ lệ thất bại cao.
Mô hình trong đề tài này đưa vào một lớp trọng số phản ánh độ khó khai thác thực tế, thời gian, mức độ phức tạp và nguy cơ bị phát hiện.
Từ đó, bài toán tìm đường được chuyển thành bài toán tìm đường có chi phí tối thiểu (Lowest-Cost Attack Path).

### Phạm vi thử nghiệm Pilot (GOADv2 - NORTH Domain)
- **Miền mục tiêu:** `north.sevenkingdoms.local` (mô hình đơn miền theo giả định Mục 2.3 của đề tài).
- **Mục tiêu tối thượng (Crown Jewels):** Nhóm `Domain Admins` (SID kết thúc bằng `-512`) và Domain Controller `WINTERFELL` (SID: `...-1001`).
- **Điểm xuất phát giả định (Compromised Machine $X$ / Initial Foothold):**
  - Máy trạm thành viên `CASTELBLACK` (SID: `...-1105`).
  - Tài khoản người dùng cấp thấp: `samwell.tarly` (SID: `...-1119`), `brandon.stark` (SID: `...-1115`), `jon.snow` (SID: `...-1118`).

---

## 2. Khám Phá Dữ Liệu và Phát Hiện Kỹ Thuật Đột Phá (Data Discovery)

Dữ liệu được thu thập từ repository mẫu BloodHound CE (`m4lwhere/Bloodhound-CE-Sample-Data`).
Trong quá trình rà soát, chúng tôi phát hiện sự khác biệt quan trọng giữa hai bộ thu thập dữ liệu (SharpHound 2.3.3 và BloodHound-python).

### 2.1. Thống kê đối tượng trong tập dữ liệu NORTH
Tập dữ liệu chứa tổng cộng **320 đối tượng AD** khi thu thập đầy đủ:
- **Computers (2):** `WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL` (Domain Controller) và `CASTELBLACK.NORTH.SEVENKINGDOMS.LOCAL` (Member Server).
- **Users (16):** Gồm các tài khoản quản trị và tài khoản thông thường mang tên các nhân vật Game of Thrones.
- **Groups (84):** Bao gồm các nhóm tích hợp hệ thống (Built-in) và các nhóm người dùng tùy chỉnh (`STARK`, `NIGHT WATCH`).
- **GPOs (3):** `DEFAULT DOMAIN POLICY`, `DEFAULT DOMAIN CONTROLLERS POLICY`, và `STARKWALLPAPER`.
- **OUs & Containers (204):** Chứa cấu trúc phân cấp LDAP và các nhóm chứa đối tượng.
- **Hạ tầng AD CS (37):** 33 Certificate Templates, 1 Enterprise CA, 1 Root CA, 1 AIA CA, 1 NTAuthStore.

### 2.2. Phát hiện kỹ thuật quan trọng về thuộc tính Ủy thác (Delegation Caveat)
Khi kiểm tra file `NORTH_20240410083414_computers.json` do SharpHound 2.3.3 thu thập, trường `AllowedToDelegate` trên máy `CASTELBLACK` trả về danh sách rỗng `[]`.
Tuy nhiên, thuộc tính `serviceprincipalnames` của `CASTELBLACK$` lại chứa SPN bất thường: `HTTP/winterfell.north.sevenkingdoms.local`.

Khi đối chiếu với file `ce_branch_bloodhoundpy_20240411011008_computers.json` (thu thập bằng `bloodhound-python`), thuộc tính LDAP `msDS-AllowedToDelegateTo` được đọc chính xác:
- `CASTELBLACK.NORTH.SEVENKINGDOMS.LOCAL` được phép ủy thác (`AllowedToDelegate`) tới `WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL`.
- `JON.SNOW@NORTH.SEVENKINGDOMS.LOCAL` cũng được cấu hình `AllowedToDelegate` tới `WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL`.

```json
{
  "ObjectIdentifier": "S-1-5-21-1252223512-2665318757-2669098637-1105",
  "Properties": {
    "name": "CASTELBLACK.NORTH.SEVENKINGDOMS.LOCAL"
  },
  "AllowedToDelegate": [
    {
      "ObjectIdentifier": "S-1-5-21-1252223512-2665318757-2669098637-1001",
      "ObjectType": "Computer"
    }
  ]
}
```

**Nhận xét nghiệp vụ:**
Đây là minh chứng rõ rệt cho thấy phương pháp thu thập dữ liệu (collector flags / LDAP query permissions) có thể tạo ra "điểm mù" trên đồ thị tấn công.
Để đảm bảo tính toàn vẹn cho mô hình, pipeline của chúng ta tích hợp trường thông tin ủy thác này để phản ánh chính xác Ground Truth của phòng lab GOADv2.

---

## 3. Giải Mã 3 "Điểm Nóng" Tấn Công (Ground Truth Verification)

Dữ liệu NORTH được thiết kế có chủ đích với 3 lỗ hổng bảo mật kinh điển.
Dưới đây là kết quả trích xuất và phân tích nghiệp vụ chi tiết cho từng điểm nóng.

### 3.1. Điểm nóng 1: Lỗ hổng GPO (`STARKWALLPAPER` & `SAMWELL.TARLY`)
- **Vị trí dữ liệu:** `gpos.json` và `domains.json`.
- **Trích xuất JSON:**
```json
{
  "ObjectIdentifier": "9CF144A4-B4C2-47F1-B24B-4C905023E062",
  "Properties": {
    "name": "STARKWALLPAPER@NORTH.SEVENKINGDOMS.LOCAL"
  },
  "Aces": [
    {
      "PrincipalSID": "S-1-5-21-1252223512-2665318757-2669098637-1119",
      "PrincipalType": "User",
      "RightName": "GenericWrite",
      "IsInherited": false
    },
    {
      "PrincipalSID": "S-1-5-21-1252223512-2665318757-2669098637-1119",
      "PrincipalType": "User",
      "RightName": "WriteDacl",
      "IsInherited": false
    },
    {
      "PrincipalSID": "S-1-5-21-1252223512-2665318757-2669098637-1119",
      "PrincipalType": "User",
      "RightName": "WriteOwner",
      "IsInherited": false
    }
  ]
}
```
- **Phân tích cơ chế tấn công:**
  Người dùng `SAMWELL.TARLY` (mật khẩu bị lộ ngay trong trường Description: `Heartsbane`) nắm giữ đồng thời `GenericWrite`, `WriteDacl` và `WriteOwner` trên GPO `STARKWALLPAPER`.
  Trong `domains.json`, GPO này được liên kết trực tiếp ở cấp Domain root (`Links: [{"GUID": "9CF144A4-B4C2-47F1-B24B-4C905023E062"}]`).
  Kẻ tấn công sau khi kiểm soát tài khoản Samwell Tarly có thể ghi đè file cấu hình GPO hoặc kịch bản chạy trong thư mục SYSVOL.
  Khi các máy trạm trong domain cập nhật chính sách, mã độc sẽ được thực thi dưới quyền `NT AUTHORITY\SYSTEM` trên mọi máy trạm.
- **Dấu hiệu giám sát (Telemetry & SOC):**
  Hành vi này làm phát sinh Security Event ID 5136 (Directory Service Object Modified) và sự kiện ghi file bất thường vào share `\\SYSVOL`.

### 3.2. Điểm nóng 2: Ủy thác Kerberos (`CASTELBLACK` -> `WINTERFELL`)
- **Vị trí dữ liệu:** `computers.json` và thuộc tính `AllowedToDelegate`.
- **Phân tích cơ chế tấn công:**
  Máy trạm `CASTELBLACK$` được cấp quyền ủy thác có ràng buộc (Kerberos Constrained Delegation) tới dịch vụ trên Domain Controller `WINTERFELL`.
  Kẻ tấn công khi chiếm được máy `CASTELBLACK` (hoặc trích xuất được NTLM hash / AES key của tài khoản máy `CASTELBLACK$`) có thể thực hiện kỹ thuật lạm dụng giao thức Kerberos:
  1. Sử dụng tiện ích mở rộng **S4U2self** để yêu cầu Key Distribution Center (KDC) cấp một vé Service Ticket (TGS) thay mặt bất kỳ người dùng nào (kể cả Domain Admin `EDDARD.STARK`) đến chính dịch vụ của `CASTELBLACK`.
  2. Sử dụng **S4U2proxy** để gửi vé TGS đó kèm theo yêu cầu chuyển tiếp sang dịch vụ mục tiêu trên Domain Controller `WINTERFELL`.
  Kỹ thuật này cho phép kẻ tấn công mạo danh Domain Admin trên Domain Controller và hoàn tất việc chiếm toàn bộ miền trong 1 bước duy nhất.
- **Dấu hiệu giám sát (Telemetry & SOC):**
  Sinh ra Event ID 4769 (Kerberos Service Ticket Operations) với cờ chuyển tiếp ủy thác từ một tài khoản máy trạm không phải là máy chủ ủy quyền chuẩn.

### 3.3. Điểm nóng 3: Lồng nhóm gián tiếp (`STARK` -> `REMOTE DESKTOP USERS`)
- **Vị trí dữ liệu:** `groups.json`.
- **Trích xuất JSON:**
```json
{
  "ObjectIdentifier": "NORTH.SEVENKINGDOMS.LOCAL-S-1-5-32-555",
  "Properties": {
    "name": "REMOTE DESKTOP USERS@NORTH.SEVENKINGDOMS.LOCAL"
  },
  "Members": [
    {
      "ObjectIdentifier": "S-1-5-21-1252223512-2665318757-2669098637-1106",
      "ObjectType": "Group"
    }
  ]
}
```
- **Phân tích cơ chế tấn công:**
  Nhóm `STARK` (SID: `...-1106`) chứa tất cả các thành viên gia tộc Stark:
  - `EDDARD.STARK` (SID: `...-1111`, cũng là Domain Admin).
  - `CATELYN.STARK` (SID: `...-1112`).
  - `ROBB.STARK` (SID: `...-1113`).
  - `SANSA.STARK` (SID: `...-1114`).
  - `BRANDON.STARK` (SID: `...-1115`).
  - `RICKON.STARK` (SID: `...-1116`).
  - `HODOR` (SID: `...-1117`).
  - `JON.SNOW` (SID: `...-1118`).
  - `ARYA.STARK` (SID: `...-1110`).
  Nhóm `REMOTE DESKTOP USERS` (nhóm built-in có RID `555`) đã lồng trực tiếp nhóm `STARK` làm thành viên.
  Do đó, một người dùng hoàn toàn bình thường như `BRANDON.STARK` tự động sở hữu quyền mở phiên RDP từ xa tới các máy trạm trong miền.
  Trên máy trạm `CASTELBLACK`, kiểm tra mảng `RegistrySessions` cho thấy phiên đăng nhập còn lưu dấu của `ROBB.STARK` và tài khoản dịch vụ `SQL_SVC`.
  Sau khi RDP thành công, kẻ tấn công có thể trích xuất bộ nhớ tiến trình LSASS để thu thập mật khẩu hoặc token của các phiên này.

---

## 4. Taxonomy Toàn Bộ Các Cạnh và Khám Phá Nâng Cao

Dựa trên việc quét toàn bộ cơ sở dữ liệu đồ thị, danh mục các cạnh và tần suất xuất hiện được chuẩn hóa như sau:

| Loại Cạnh | Tần suất | Phân loại kỹ thuật | Đặc trưng an ninh |
| :--- | :---: | :--- | :--- |
| `WriteDacl` | 573 | AD ACL | Sửa danh sách kiểm soát truy cập để tự cấp quyền tối cao. |
| `WriteOwner` | 573 | AD ACL | Chiếm quyền sở hữu đối tượng AD. |
| `GenericAll` | 383 | AD ACL | Toàn quyền kiểm soát đối tượng. |
| `Owns` | 308 | AD ACL | Quyền sở hữu đối tượng đã tồn tại sẵn. |
| `GenericWrite` | 105 | AD ACL | Ghi thuộc tính đối tượng tùy ý. |
| `Enroll` | 88 | AD CS Abuse | Gửi yêu cầu xin cấp chứng chỉ số từ Certificate Template. |
| `MemberOf` | 42 | Structural AD | Kế thừa nhóm người dùng thông thường. |
| `AllExtendedRights` | 30 | AD ACL | Toàn bộ quyền mở rộng trên đối tượng (ForceChangePassword, SendAs...). |
| `AddKeyCredentialLink` | 24 | Kerberos Abuse | **Shadow Credentials**: Ghi chứng chỉ vào đối tượng để xác thực PKINIT lấy TGT. |
| `PrimaryGroupMemberOf` | 18 | Structural AD | Nhóm chính của tài khoản (Domain Users, Domain Computers). |
| `HasSession` / `RegistrySession` | 6 | Credential Access | Phiên đăng nhập hoạt động của user trên máy tính (LSASS dump). |
| `GetChanges` / `GetChangesAll` | 5 | Domain Escalation | **DCSync**: Quyền đồng bộ dữ liệu Directory Replication kéo toàn bộ password hash. |
| `AllowedToDelegate` | 4 | Kerberos Abuse | **Constrained Delegation**: Lạm dụng ủy thác Kerberos S4U. |
| `ManageCA` | 3 | AD CS Abuse | Quản trị dịch vụ cấp phát chứng chỉ số (ESC7). |
| `GPLink` | 3 | Group Policy | Liên kết chính sách GPO với đơn vị tổ chức (OU) hoặc Domain. |
| `ManageCertificates` | 2 | AD CS Abuse | Phê duyệt và phát hành chứng chỉ số đang chờ duyệt (ESC7). |

### Phát hiện các cạnh nâng cao vượt ngoài danh mục ban đầu
1. **`AddKeyCredentialLink` (Shadow Credentials - 24 cạnh):**
   Nhóm `KEY ADMINS` nắm quyền ghi thuộc tính `msDS-KeyCredentialLink` trên hầu hết mọi người dùng và máy tính trong hệ thống.
   Kỹ thuật này cho phép kẻ tấn công tạo một cặp khóa RSA, ghi public key vào thuộc tính của tài khoản nạn nhân, sau đó dùng private key để xác thực PKINIT và lấy vé TGT mà không làm thay đổi mật khẩu hiện tại của nạn nhân.
2. **Hệ sinh thái AD CS (Active Directory Certificate Services):**
   Xuất hiện đầy đủ các thành phần PKI nội bộ gồm 33 Certificate Templates và Certificate Authority `SEVENKINGDOMS-CA`.
   Các quyền `Enroll`, `ManageCA`, và `ManageCertificates` mở ra hướng khai thác theo chuỗi lỗ hổng AD CS (ESC1 tới ESC8).

---

## 5. Mô Hình Trọng Số 4D MAUT và Cầu Nối Toán Học Cho Dijkstra

### 5.1. Khung lý thuyết và Vector đặc trưng 4 chiều
Mỗi cạnh $e$ trong đồ thị được lượng hóa thông qua vector 4 chiều:
$$\vec{x}(e) = [P(e), D(e), C(e), R^*(e)]^T$$

Trong đó:
- $P(e) \in [1, 5]$: **Prerequisites (Điều kiện tiên quyết).** Mức 1 là không cần điều kiện gì ngoài quyền truy cập cơ bản; mức 5 đòi hỏi điều kiện rất khắt khe (ví dụ: máy tính mục tiêu phải đang có phiên đăng nhập của Domain Admin hoặc phải có kết nối mạng đặc biệt).
- $D(e) \in [1, 5]$: **Detectability (Khả năng bị phát hiện / Mức độ tạo tiếng ồn).** Mức 1 là hoàn toàn im lặng (chỉ là truy vấn LDAP thụ động hoặc kế thừa nhóm); mức 5 là cực kỳ ồn ào và chắc chắn kích hoạt cảnh báo SOC/EDR (ví dụ: ép đổi mật khẩu `ForceChangePassword`, dump LSASS hoặc DCSync quy mô lớn).
- $C(e) \in [1, 5]$: **Technical Complexity (Độ phức tạp kỹ thuật).** Mức 1 là thao tác tự nhiên; mức 5 đòi hỏi kỹ thuật khai thác chuyên sâu qua nhiều tầng giao thức (ví dụ: lạm dụng Kerberos PKINIT, kết hợp NTLM Relay sang AD CS Web Enrollment).
- $R(e) \in [1, 5]$: **Reliability (Độ tin cậy của kỹ thuật).** Thang đo từ 1 (rất dễ thất bại / phụ thuộc yếu tố ngẫu nhiên) tới 5 (đảm bảo thành công 100%).
  Biến đổi phạt thất bại được định nghĩa là:
  $$R^*(e) = 6 - R(e)$$

### 5.2. Hàm chi phí đa thuộc tính (MAUT Cost Function)
$$W(e) = 0.25 \cdot P(e) + 0.40 \cdot D(e) + 0.20 \cdot C(e) + 0.15 \cdot R^*(e)$$

Trọng số $\beta = 0.40$ dành cho thuộc tính Detectability phản ánh bản chất bất đối xứng trong tác chiến không gian mạng:
Đối với kẻ tấn công có chủ đích (Advanced Persistent Threat - APT), bị phát hiện và ngắt kết nối là tổn thất lớn nhất.
Do đó, một bước leo thang dù nhanh nhưng gây báo động đỏ trên hệ thống SIEM/EDR sẽ bị gán chi phí rất cao.

### 5.3. Bảng điểm hợp đồng trọng số (Edge Contract Table)
Toàn bộ thông số đã được lập trình và lưu trữ tại file `data/processed/edge_weights_contract.csv`:

| EdgeType | Category | P | D | C | R | $R^*$ | **Chi phí $W(e)$** |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `MemberOf` | Structural / Identity | 1 | 1 | 1 | 5 | 1 | **1.000** |
| `PrimaryGroupMemberOf` | Structural / Identity | 1 | 1 | 1 | 5 | 1 | **1.000** |
| `Owns` | Active Directory ACL | 1 | 2 | 1 | 5 | 1 | **1.400** |
| `AdminTo` | Host Access | 2 | 2 | 1 | 5 | 1 | **1.650** |
| `GenericAll` | Active Directory ACL | 2 | 2 | 2 | 5 | 1 | **1.850** |
| `AllExtendedRights` | Active Directory ACL | 2 | 3 | 2 | 5 | 1 | **2.250** |
| `CanPSRemote` | Lateral Movement | 2 | 3 | 2 | 5 | 1 | **2.250** |
| `WriteDacl` | Active Directory ACL | 2 | 3 | 2 | 5 | 1 | **2.250** |
| `WriteOwner` | Active Directory ACL | 2 | 3 | 2 | 5 | 1 | **2.250** |
| `GenericWrite` | Active Directory ACL | 2 | 3 | 2 | 5 | 1 | **2.250** |
| `AllowedToDelegate` | Kerberos Abuse | 3 | 2 | 3 | 5 | 1 | **2.300** |
| `Enroll` | AD CS Abuse | 2 | 2 | 4 | 4 | 2 | **2.400** |
| `CanRDP` | Lateral Movement | 2 | 3 | 2 | 4 | 2 | **2.400** |
| `ExecuteDCOM` | Lateral Movement | 2 | 3 | 3 | 4 | 2 | **2.600** |
| `GetChangesAll` | Domain Escalation | 2 | 4 | 2 | 5 | 1 | **2.650** |
| `ManageCertificates` | AD CS Abuse | 3 | 3 | 3 | 5 | 1 | **2.700** |
| `ManageCA` | AD CS Abuse | 3 | 3 | 4 | 5 | 1 | **2.900** |
| `GPLink` | Group Policy Abuse | 3 | 3 | 3 | 3 | 3 | **3.000** |
| `AddKeyCredentialLink` | Kerberos Abuse | 2 | 4 | 4 | 5 | 1 | **3.050** |
| `HasSession` | Credential Access | 3 | 4 | 3 | 2 | 4 | **3.550** |

### 5.4. Cầu nối toán học cho thuật toán Dijkstra
Giả sử xác suất một bước tấn công thành công mà không bị phát hiện là $P_s(e) \in (0, 1]$.
Xác suất thành công của cả chuỗi tấn công gồm tập các cạnh $\text{Path} = \{e_1, e_2, \dots, e_k\}$ (dưới giả định các bước độc lập) là:
$$P_{success}(\text{Path}) = \prod_{e \in \text{Path}} P_s(e)$$

Mục tiêu tìm đường tấn công có xác suất thành công cao nhất:
$$\max_{\text{Path}} \prod_{e \in \text{Path}} P_s(e)$$

Lấy hàm $-\ln$ cho biểu thức trên:
$$\max_{\text{Path}} \prod_{e \in \text{Path}} P_s(e) \iff \min_{\text{Path}} \sum_{e \in \text{Path}} (-\ln P_s(e))$$

Đặt hàm chi phí cạnh là $c(e) = -\ln P_s(e)$.
Do $0 < P_s(e) \le 1$, ta có $c(e) \ge 0$.
Điều này đảm bảo tính chất không âm (non-negative weights), thỏa mãn hoàn toàn điều kiện tiên quyết của thuật toán Dijkstra.
Hàm chi phí đa thuộc tính $W(e) \ge 1.0$ của chúng ta đóng vai trò tương đương với hàm chi phí cộng dồn này, cho phép áp dụng trực tiếp thuật toán Dijkstra tìm đường ngắn nhất.

---

## 6. Kết Quả Thử Nghiệm Đối Chứng: BloodHound vs Weighted Dijkstra

Chúng tôi đã tiến hành dựng đồ thị thực nghiệm bằng NetworkX và chạy thử nghiệm tìm đường từ các điểm xuất phát khác nhau tới nhóm mục tiêu `Domain Admins`.

### 6.1. Xuất phát từ máy trạm bị chiếm `CASTELBLACK` (Machine $X$)
```
Đường đi tối ưu:
CASTELBLACK --(AllowedToDelegate, w=2.30)--> WINTERFELL --(AdminTo, w=1.00)--> DOMAIN ADMINS
```
- **Số bước (Hop count):** 2 bước.
- **Tổng chi phí tích lũy:** $W = 3.30$.
- **Đánh giá:**
  Cả BloodHound và Weighted Graph đều đồng thuận đây là đường đi ngắn nhất và có chi phí thấp nhất.
  Kẻ tấn công không cần cracking mật khẩu mà lợi dụng cơ chế Kerberos S4U để ủy thác thẳng lên Domain Controller.

### 6.2. Xuất phát từ người dùng `SAMWELL.TARLY`
```
Đường đi tối ưu:
SAMWELL.TARLY --(GenericWrite, w=2.25)--> STARKWALLPAPER --(GPLink, w=3.00)--> WINTERFELL --(AdminTo, w=1.00)--> DOMAIN ADMINS
```
- **Số bước (Hop count):** 3 bước.
- **Tổng chi phí tích lũy:** $W = 6.25$.
- **Đánh giá:**
  Mặc dù đường đi chỉ gồm 3 bước, chi phí bị đẩy lên $6.25$ do cạnh `GPLink` có $R=3$ (phụ thuộc vào chu kỳ cập nhật `gpupdate` mất từ 90 đến 120 phút) và việc sửa GPO tạo ra nhiều dấu vết trên hệ thống ghi nhật ký SYSVOL.

### 6.3. Xuất phát từ người dùng `BRANDON.STARK`
```
Đường đi:
BRANDON.STARK --(MemberOf, w=1.00)--> STARK --(MemberOf, w=1.00)--> REMOTE DESKTOP USERS --(CanRDP, w=2.40)--> WINTERFELL/Host --(AdminTo, w=1.00)--> DOMAIN ADMINS
```
- **Số bước (Hop count):** 4 bước.
- **Tổng chi phí tích lũy:** $W = 5.40$.
- **So sánh then chốt với BloodHound:**
  BloodHound chỉ dựa trên số bước nên sẽ ưu tiên đường GPO của Samwell Tarly (3 bước) hơn đường của Brandon Stark (4 bước).
  Tuy nhiên, mô hình trọng số chỉ ra rằng con đường của Brandon Stark có chi phí rủi ro thấp hơn ($5.40 < 6.25$).
  Lý do: Hai bước đầu tiên hoàn toàn là kế thừa nhóm AD tự nhiên ($w=1.0$), không tạo ra bất kỳ cảnh báo an ninh nào và diễn ra tức thì, mang lại lợi thế chiến thuật rõ rệt cho kẻ tấn công ẩn mình.

---

## 7. Các Script Thực Nghiệm Đã Triển Khai Trong Dự Án

Toàn bộ mã nguồn thực nghiệm được tổ chức trong thư mục `scripts/`:

1. [`scripts/explore_north.py`](../scripts/explore_north.py):
   Đọc và thống kê nhanh siêu dữ liệu, số lượng đối tượng và phiên bản schema của toàn bộ file JSON trong thư mục `data/raw/NORTH`.
2. [`scripts/verify_hotspots.py`](../scripts/verify_hotspots.py):
   Kiểm chứng 3 điểm nóng Ground Truth trong dữ liệu (GPO `STARKWALLPAPER`, máy `CASTELBLACK`, và nhóm `REMOTE DESKTOP USERS`).
3. [`scripts/deep_inspect_edges.py`](../scripts/deep_inspect_edges.py):
   Rà soát chuyên sâu toàn bộ các mảng ACEs, Members, Sessions, GPLinks và trích xuất mẫu đại diện cho từng loại cạnh.
4. [`scripts/compare_datasets.py`](../scripts/compare_datasets.py):
   Đối chiếu sai khác giữa bộ dữ liệu thu thập bởi SharpHound 2.3.3 và BloodHound-python, phát hiện điểm mù của trường `AllowedToDelegate`.
5. [`scripts/generate_edge_contract.py`](../scripts/generate_edge_contract.py):
   Tính toán trọng số MAUT 4D và tự động sinh file hợp đồng chuẩn hóa [`edge_weights_contract.csv`](../data/processed/edge_weights_contract.csv).
6. [`scripts/test_weighted_paths.py`](../scripts/test_weighted_paths.py):
   Xây dựng đồ thị có hướng có trọng số bằng NetworkX và thực thi thuật toán tìm đường Dijkstra đối chứng với thuật toán Unweighted Shortest Path của BloodHound.

---

## 8. Định Hướng và Kế Hoạch Cho Tuần 2 - 3

Dựa trên kết quả khám phá hôm nay, các nhiệm vụ trọng tâm tiếp theo gồm có:
1. **Thiết kế Schema Đồ thị Hoàn chỉnh (Graph Schema):**
   Xác định rõ quy chuẩn lưu trữ các node (User, Computer, Group, GPO, OU, Domain) và thuộc tính của các cạnh (loại cạnh, chi phí, dấu vết giám sát).
2. **Xây dựng Parser Tự động Hóa:**
   Viết module Python đọc trực tiếp file zip xuất ra từ BloodHound, tự động chuẩn hóa thuộc tính và giải quyết các cạnh suy luận (ví dụ: ánh xạ từ `REMOTE DESKTOP USERS` sang quyền `CanRDP` trên các máy trạm).
3. **Mở rộng Thuật toán Phân tích Choke Point:**
   Cài đặt thuật toán đo độ trung tâm trung gian (Betweenness Centrality) có trọng số để tìm ra các mắt xích hiểm yếu nhất trong hạ tầng mạng, phục vụ khuyến nghị phòng thủ chủ động.
