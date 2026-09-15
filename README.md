# Identity - Asset Graph & Attack Path Analysis

Hệ thống mô hình hóa đồ thị quan hệ Danh tính - Tài sản (Identity - Asset) và phân tích đường tấn công có trọng số trong Active Directory (AD).

Dự án này giải quyết câu hỏi cốt lõi:
*"Nếu kẻ tấn công chiếm được máy X, chúng có thể đi tới đâu, theo con đường nào và với chi phí rủi ro/khả năng khai thác thấp nhất là bao nhiêu?"*

Khác với BloodHound mặc định chỉ đếm số bước nhảy (Unweighted Shortest Path), hệ thống này tích hợp mô hình trọng số đa thuộc tính 4D MAUT (Multi-Attribute Utility Theory) phản ánh độ khó khai thác, thời gian, độ tin cậy và mức độ cảnh báo phát hiện của EDR/SOC.

---

## Báo Cáo Nghiên Cứu Chi Tiết

Tất cả phân tích chi tiết, giải mã dữ liệu và cơ sở toán học đã được tổng hợp tại:
- **Tài liệu nghiên cứu khám phá dữ liệu:** [`docs/01_data_discovery_and_weighting_model.md`](docs/01_data_discovery_and_weighting_model.md)
- **Báo cáo chuyên sâu biện luận trọng số cạnh:** [`docs/02_edge_weighting_model_and_reasoning.md`](docs/02_edge_weighting_model_and_reasoning.md)
- **Báo cáo nghiệm thu Tuần 1 (Dữ liệu, Cơ chế AD & ACL, Kiến trúc Lược đồ):** [`docs/03_week1_data_ad_acl_and_schema_report.md`](docs/03_week1_data_ad_acl_and_schema_report.md)
- **Hợp đồng trọng số các cạnh:** [`data/processed/edge_weights_contract.csv`](data/processed/edge_weights_contract.csv)

---

## Tóm Tắt Khám Phá Dữ Liệu & Điểm Nóng Ground Truth (Domain NORTH)

Dataset pilot được lựa chọn từ phòng lab GOADv2 (Game of Active Directory v2) đơn miền `north.sevenkingdoms.local`.
Mục tiêu tối thượng (Crown Jewels) gồm nhóm `Domain Admins` (SID kết thúc bằng `-512`) và Domain Controller `WINTERFELL`.

### 1. Kiểm chứng 3 "Điểm nóng" Ground Truth
1. **Lỗ hổng GPO (`STARKWALLPAPER` & `SAMWELL.TARLY`):**
   User `SAMWELL.TARLY` sở hữu đồng thời `GenericWrite`, `WriteDacl` và `WriteOwner` trên GPO `STARKWALLPAPER`.
   GPO này liên kết trực tiếp ở cấp Domain root (`NORTH.SEVENKINGDOMS.LOCAL`), cho phép kẻ tấn công sửa GPO trên SYSVOL để thực thi mã dưới quyền `NT AUTHORITY\SYSTEM` trên toàn bộ máy trạm.
2. **Ủy thác Kerberos (`CASTELBLACK` -> `WINTERFELL`):**
   Máy trạm `CASTELBLACK$` được cấp quyền Kerberos Constrained Delegation (`AllowedToDelegate`) tới dịch vụ trên Domain Controller `WINTERFELL`.
   Kẻ tấn công lạm dụng kỹ thuật S4U2self và S4U2proxy để mạo danh Domain Admin trên Domain Controller và chiếm toàn quyền kiểm soát miền chỉ trong 1 bước.
   *Phát hiện kỹ thuật quan trọng:* Thuộc tính này bị rỗng trong bản thu thập SharpHound 2.3.3 nhưng được trích xuất chính xác trong bản `bloodhound-python`.
3. **Lồng nhóm gián tiếp (`STARK` -> `REMOTE DESKTOP USERS`):**
   Nhóm `STARK` (chứa 9 người dùng họ Stark như Brandon, Arya, Jon Snow) được lồng trực tiếp vào nhóm built-in `REMOTE DESKTOP USERS`.
   Nhờ đó, user cấp thấp như `BRANDON.STARK` tự động có quyền RDP tới các máy trạm có phiên đăng nhập của quản trị viên và tài khoản dịch vụ.

---

## Mô Hình Trọng Số 4D MAUT

Mỗi cạnh $e$ được gán vector 4 chiều:
$$\vec{x}(e) = [P(e), D(e), C(e), R^*(e)]^T$$

Trong đó:
- $P(e) \in [1, 5]$: Điều kiện tiên quyết (Prerequisites).
- $D(e) \in [1, 5]$: Mức độ bị phát hiện / Tiếng ồn EDR/SOC (Detectability).
- $C(e) \in [1, 5]$: Độ phức tạp kỹ thuật (Technical Complexity).
- $R(e) \in [1, 5]$: Độ tin cậy thành công của kỹ thuật (Reliability), với $R^*(e) = 6 - R(e)$.

Hàm chi phí đa thuộc tính:
$$W(e) = 0.25 \cdot P(e) + 0.40 \cdot D(e) + 0.20 \cdot C(e) + 0.15 \cdot R^*(e)$$

Hệ số $\beta = 0.40$ phản ánh chi phí bất đối xứng khi kẻ tấn công có chủ đích (APT) bị hệ thống phòng thủ phát hiện.
Khi biểu diễn xác suất thành công là $P_s(e)$, bài toán tối đa hóa xác suất tương đương với việc tối thiểu hóa tổng chi phí:
$$\max \prod P_s(e) \iff \min \sum (-\ln P_s(e))$$
Điều này tạo cầu nối toán học hoàn chỉnh để áp dụng trực tiếp thuật toán Dijkstra.

### Bảng Trọng Số Các Cạnh Phổ Biến

| Loại Cạnh (Edge Type) | Nhóm | Chi phí $W(e)$ | Mô tả ngắn |
| :--- | :--- | :---: | :--- |
| `MemberOf` | Structural | 1.000 | Kế thừa nhóm AD tự nhiên, hoàn toàn im lặng. |
| `PrimaryGroupMemberOf` | Structural | 1.000 | Thành viên nhóm chính của tài khoản. |
| `Owns` | ACL | 1.400 | Đã là Owner, chỉ cần 1 bước sửa DACL. |
| `AdminTo` | Host Access | 1.650 | Quyền Local Admin trực tiếp trên máy chủ. |
| `GenericAll` | ACL | 1.850 | Toàn quyền kiểm soát đối tượng AD. |
| `WriteDacl` / `WriteOwner` | ACL | 2.250 | Sửa DACL hoặc đổi Owner đối tượng (sinh Event 5136). |
| `GenericWrite` | ACL | 2.250 | Ghi thuộc tính đối tượng (sửa GPO, gán SPN). |
| `CanPSRemote` | Lateral Movement | 2.250 | Thực thi lệnh qua WinRM (PowerShell Event 4104). |
| `AllowedToDelegate` | Kerberos | 2.300 | Ủy thác Kerberos S4U2self + S4U2proxy. |
| `CanRDP` | Lateral Movement | 2.400 | Kết nối RDP (Port 3389, Event 4624 Type 10). |
| `GetChangesAll` | Domain Escalation | 2.650 | DCSync kéo toàn bộ mật khẩu miền (Event 4662). |
| `GPLink` | Group Policy | 3.000 | Áp đặt GPO, phụ thuộc thời gian chu kỳ gpupdate. |
| `AddKeyCredentialLink` | Kerberos | 3.050 | Shadow Credentials qua PKINIT (Event 5136 rõ rệt). |
| `HasSession` | Credential Access | 3.550 | Dump LSASS trích xuất token phiên đăng nhập (ồn ào, dễ xịt). |

---

## Kết Quả Thử Nghiệm Tìm Đường Tấn Công

Thực nghiệm tìm đường tới `DOMAIN ADMINS` trên đồ thị xây dựng từ dữ liệu NORTH:

1. **Từ máy `CASTELBLACK` (Machine $X$ bị chiếm):**
   `CASTELBLACK` --(`AllowedToDelegate`, $w=2.30$)--> `WINTERFELL` --(`AdminTo`, $w=1.00$)--> `DOMAIN ADMINS`
   - Số bước: 2 bước.
   - Tổng chi phí $W = 3.30$.
2. **Từ người dùng `SAMWELL.TARLY`:**
   `SAMWELL.TARLY` --(`GenericWrite`, $w=2.25$)--> `STARKWALLPAPER` --(`GPLink`, $w=3.00$)--> `WINTERFELL` --(`AdminTo`, $w=1.00$)--> `DOMAIN ADMINS`
   - Số bước: 3 bước.
   - Tổng chi phí $W = 6.25$.
3. **Từ người dùng `BRANDON.STARK`:**
   `BRANDON.STARK` --(`MemberOf`, $w=1.00$)--> `STARK` --(`MemberOf`, $w=1.00$)--> `REMOTE DESKTOP USERS` --(`CanRDP`, $w=2.40$)--> Host --(`AdminTo`, $w=1.00$)--> `DOMAIN ADMINS`
   - Số bước: 4 bước.
   - Tổng chi phí $W = 5.40$.

**Điểm khác biệt cốt lõi:**
BloodHound ưu tiên đường 3 bước của Samwell Tarly hơn đường 4 bước của Brandon Stark.
Tuy nhiên, mô hình trọng số chỉ ra đường của Brandon Stark tối ưu hơn về mặt rủi ro ($5.40 < 6.25$) vì tận dụng được 2 bước kế thừa nhóm tự nhiên không phát sinh cảnh báo SOC.

---

## Cấu Trúc Dự Án

```
├── README.md
├── docs/
│   └── 01_data_discovery_and_weighting_model.md  # Báo cáo kỹ thuật chi tiết
├── data/
│   ├── processed/
│   │   └── edge_weights_contract.csv             # Hợp đồng trọng số các cạnh
│   └── raw/
│       ├── NORTH/                                # Dữ liệu thô từ SharpHound 2.3.3
│       └── NORTH_CE_PYTHON/                      # Dữ liệu đối chứng từ bloodhound-python
├── scripts/
│   ├── explore_north.py                          # Khám phá cấu trúc dữ liệu thô
│   ├── verify_hotspots.py                        # Kiểm chứng 3 điểm nóng Ground Truth
│   ├── deep_inspect_edges.py                     # Quét và trích xuất mọi cạnh thực tế
│   ├── compare_datasets.py                       # Đối chiếu sai lệch giữa 2 collector
│   ├── generate_edge_contract.py                 # Tính toán và xuất file contract CSV
│   └── test_weighted_paths.py                    # Dựng đồ thị và thử nghiệm Dijkstra
├── pyproject.toml
└── uv.lock
```

---

## Hướng Dẫn Chạy Thử Nghiệm

Dự án sử dụng trình quản lý gói `uv` và môi trường ảo Python:

```bash
# Cài đặt phụ thuộc
uv sync

# Kiểm chứng 3 điểm nóng Ground Truth
uv run python scripts/verify_hotspots.py

# Sinh lại file hợp đồng trọng số
uv run python scripts/generate_edge_contract.py

# Chạy kiểm thử tìm đường tấn công Dijkstra có trọng số
uv run python scripts/test_weighted_paths.py
```
