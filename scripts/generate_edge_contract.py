import csv
import pandas as pd

# Define the edge scoring based on AD domain expertise & the 4D MAUT model:
# Vector: [P, D, C, R]
# R* = 6 - R
# W = 0.25*P + 0.40*D + 0.20*C + 0.15*R*

edge_definitions = [
    {
        "edge_type": "MemberOf",
        "category": "Structural / Identity",
        "technique": "Native Active Directory Group Membership",
        "P": 1, "D": 1, "C": 1, "R": 5,
        "description": "Quan hệ thành viên nhóm tĩnh trong AD. Khai thác tự nhiên, không cần điều kiện, không sinh log bất thường, độ tin cậy 100%."
    },
    {
        "edge_type": "PrimaryGroupMemberOf",
        "category": "Structural / Identity",
        "technique": "Primary Group Membership (RID matching)",
        "P": 1, "D": 1, "C": 1, "R": 5,
        "description": "Nhóm chính của tài khoản (mặc định Domain Users/Domain Computers). Hoàn toàn tự nhiên và thụ động."
    },
    {
        "edge_type": "AdminTo",
        "category": "Host Access / Privilege",
        "technique": "Local Administrator Rights on Target Machine",
        "P": 2, "D": 2, "C": 1, "R": 5,
        "description": "Quyền Local Admin trên host đích. Cho phép thực thi lệnh mức SYSTEM hoặc dump credentials (sinh Event 4624/4672)."
    },
    {
        "edge_type": "CanRDP",
        "category": "Lateral Movement",
        "technique": "Remote Desktop Protocol Logon (Port 3389)",
        "P": 2, "D": 3, "C": 2, "R": 4,
        "description": "Đăng nhập RDP vào máy chủ. Sinh Event 4624 Type 10 và RDS session log. Phụ thuộc firewall và service RDP đang chạy."
    },
    {
        "edge_type": "CanPSRemote",
        "category": "Lateral Movement",
        "technique": "WinRM / PowerShell Remoting (Port 5985/5986)",
        "P": 2, "D": 3, "C": 2, "R": 5,
        "description": "Thực thi PowerShell qua WinRM. Sinh Event 4104 (Script Block Logging) và Network Logon 4624 Type 3."
    },
    {
        "edge_type": "ExecuteDCOM",
        "category": "Lateral Movement",
        "technique": "Distributed COM Object Execution (Port 135/RPC)",
        "P": 2, "D": 3, "C": 3, "R": 4,
        "description": "Khởi tạo DCOM object (e.g. MMC20.Application, ShellWindows) để thực thi lệnh từ xa. Cần RPC port và DCOM permissions."
    },
    {
        "edge_type": "GenericAll",
        "category": "Active Directory ACL",
        "technique": "Full Object Control (Modify DACL, Reset Password, SPN, etc.)",
        "P": 2, "D": 2, "C": 2, "R": 5,
        "description": "Toàn quyền kiểm soát đối tượng. Cho phép gán thêm quyền hoặc đổi thuộc tính qua LDAP. Độ tin cậy tuyệt đối."
    },
    {
        "edge_type": "WriteDacl",
        "category": "Active Directory ACL",
        "technique": "Modify Discretionary Access Control List (DACL)",
        "P": 2, "D": 3, "C": 2, "R": 5,
        "description": "Sửa DACL để tự cấp GenericAll cho tài khoản của mình. Sinh Event 5136 (Directory Service Object Modified)."
    },
    {
        "edge_type": "WriteOwner",
        "category": "Active Directory ACL",
        "technique": "Take Ownership of AD Object",
        "P": 2, "D": 3, "C": 2, "R": 5,
        "description": "Cướp quyền sở hữu đối tượng AD (Owner). Sau khi chiếm Owner, tiến hành sửa DACL -> GenericAll. Sinh Event 5136."
    },
    {
        "edge_type": "Owns",
        "category": "Active Directory ACL",
        "technique": "Pre-existing Object Ownership",
        "P": 1, "D": 2, "C": 1, "R": 5,
        "description": "Đã là Owner của đối tượng, có quyền tự thêm WriteDacl mà không cần leo thang thêm."
    },
    {
        "edge_type": "GenericWrite",
        "category": "Active Directory ACL",
        "technique": "Arbitrary Attribute Modification",
        "P": 2, "D": 3, "C": 2, "R": 5,
        "description": "Ghi thuộc tính tùy ý. Tùy thuộc đối tượng (nếu là GPO thì sửa cấu hình/script; nếu là User thì gán SPN để Kerberoast hoặc msDS-AllowedToDelegateTo)."
    },
    {
        "edge_type": "AllExtendedRights",
        "category": "Active Directory ACL",
        "technique": "Extended AD Rights (Password Reset, Replicating, etc.)",
        "P": 2, "D": 3, "C": 2, "R": 5,
        "description": "Tập hợp tất cả Extended Rights trên đối tượng (bao gồm User-Force-Change-Password nếu trên User, hoặc DCSync nếu trên Domain)."
    },
    {
        "edge_type": "AllowedToDelegate",
        "category": "Kerberos Abuse",
        "technique": "Kerberos Constrained Delegation (S4U2self + S4U2proxy)",
        "P": 3, "D": 2, "C": 3, "R": 5,
        "description": "Ủy thác Kerberos có ràng buộc. Tài khoản máy/dịch vụ dùng S4U2self xin vé thay mặt Domain Admin và dùng S4U2proxy truy cập dịch vụ trên máy đích. Cực kỳ tin cậy, log TGS-REQ bình thường khó phân biệt."
    },
    {
        "edge_type": "GPLink",
        "category": "Group Policy Abuse",
        "technique": "GPO Deployment to Linked Container/Host (Immediate Task/Script)",
        "P": 3, "D": 3, "C": 3, "R": 3,
        "description": "Liên kết GPO tới OU/Domain. Khi sửa GPO, mã độc thực thi với quyền SYSTEM trên máy con. Điểm trừ: R = 3 vì phải chờ chu kỳ gpupdate (90-120 phút) hoặc trigger gpupdate /force."
    },
    {
        "edge_type": "HasSession",
        "category": "Credential Access",
        "technique": "Token Impersonation / LSASS Memory Credential Dumping",
        "P": 3, "D": 4, "C": 3, "R": 2,
        "description": "Chiếm quyền user có phiên đăng nhập trên máy. Cần quyền Local Admin trên máy. Khá ồn (LSASS access kích hoạt EDR/Sysmon 10), R=2 vì user có thể đăng xuất hoặc Credential Guard bật."
    },
    {
        "edge_type": "AddKeyCredentialLink",
        "category": "Kerberos Abuse",
        "technique": "Shadow Credentials via PKINIT (msDS-KeyCredentialLink)",
        "P": 2, "D": 4, "C": 4, "R": 5,
        "description": "Ghi chứng chỉ công khai vào thuộc tính msDS-KeyCredentialLink của đối tượng để xác thực Kerberos PKINIT lấy TGT. Sinh Event 5136 rõ rệt nhưng độ tin cậy kỹ thuật rất cao."
    },
    {
        "edge_type": "GetChangesAll",
        "category": "Domain Escalation",
        "technique": "DCSync Attack (MS-DRSR Domain Replication)",
        "P": 2, "D": 4, "C": 2, "R": 5,
        "description": "Tấn công DCSync giả lập Domain Controller kéo hash mật khẩu của mọi user từ xa qua giao thức DRSR. Cực kỳ nhanh, tin cậy tuyệt đối, nhưng sinh Event 4662 bị EDR/SOC giám sát gắt gao."
    },
    {
        "edge_type": "Enroll",
        "category": "AD CS Abuse",
        "technique": "AD Certificate Services Template Enrollment (ESC1 - ESC8)",
        "P": 2, "D": 2, "C": 4, "R": 4,
        "description": "Yêu cầu cấp chứng chỉ số từ template có lỗ hổng cấu hình (ví dụ ESC1: SAN giả mạo Domain Admin). Cần CA đang hoạt động và thẩm tra chứng chỉ."
    },
    {
        "edge_type": "ManageCA",
        "category": "AD CS Abuse",
        "technique": "Active Directory Certificate Services CA Full Control",
        "P": 3, "D": 3, "C": 4, "R": 5,
        "description": "Quyền quản trị CA server (ESC7). Cho phép bật cờ cấu hình nguy hiểm hoặc cấp duyệt certificate bất kỳ."
    },
    {
        "edge_type": "ManageCertificates",
        "category": "AD CS Abuse",
        "technique": "Certificate Officer Rights (Issue Failed/Pending Requests)",
        "P": 3, "D": 3, "C": 3, "R": 5,
        "description": "Quyền Officer cho phép duyệt phát hành các yêu cầu chứng chỉ đang pending (ESC7 part 2)."
    }
]

rows = []
for item in edge_definitions:
    p = item["P"]
    d = item["D"]
    c = item["C"]
    r = item["R"]
    r_star = 6 - r
    w = round(0.25 * p + 0.40 * d + 0.20 * c + 0.15 * r_star, 3)
    
    # Calculate equivalent probability Ps and -ln(Ps)
    # Ps can be normalized from w in [1.0, 5.0] to (0, 1]
    # For example Ps = exp(-alpha * (w - 1)) or similar, or W can be used directly as Dijkstra cost
    rows.append({
        "EdgeType": item["edge_type"],
        "Category": item["category"],
        "P_Prerequisites": p,
        "D_Detectability": d,
        "C_Complexity": c,
        "R_Reliability": r,
        "R_Star": r_star,
        "Weight_MAUT": w,
        "Technique": item["technique"],
        "Description": item["description"]
    })

df = pd.DataFrame(rows)
df.sort_values(by="Weight_MAUT", inplace=True)
csv_path = "data/processed/edge_weights_contract.csv"
df.to_csv(csv_path, index=False)
print(f"Saved edge contract to {csv_path}")
print("\n--- SUMMARY TABLE ---")
print(df[["EdgeType", "Category", "Weight_MAUT", "P_Prerequisites", "D_Detectability", "C_Complexity", "R_Reliability"]].to_string(index=False))
