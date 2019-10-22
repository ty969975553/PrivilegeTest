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

以管理员帐户登录，以管理员方式运行：isAdmin=TRUE   ElevationType=TokenElevationTypeFull    //进程的权限没有被阉割

以管理员帐户登录，以普通方式运行：isAdmin=false   ElevationType=TokenElevationTypeLitmited   //进程权限被阉割

以普通用户登录，以管理员方式运行：isAdmin=TRUE   ElevationType=TokenElevationTypeFull    //进程的权限被提升了

以普通用户登录，以普通方式运行：isAdmin=false   ElevationType=TokenElevationTypeDefault   //进程权限和用户相同，没有被提升

