# PrivilegeTest
PrivilegeTest


结果 | PrivilegeTest::IsUserAdmin() | PrivilegeTest::IsRunasAdmin() | PrivilegeTest::GetProcessTokenElevationTypeStaus() | ::IsUserAnAdmin() 
---|--- |--- |--- |---
win7 管理员用户 |  0 | 0 | 1 | 0
win7 管理员用户uac提权后执行| 1 | 1 | 1 | 1
win7 标准用户直接执行| 0 | 0 | 0 | 0
win7 标准用户uac提权后执行| 1 | 1 | 0 | 1
winxp 直接运行| 1 | 0 | 0 | 1
winxp -runas直接运行 | 1 | 0 | 0 | 1