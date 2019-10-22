// Windows 头文件:
#include <windows.h>

// system
#include <Shlwapi.h>
#include <ShlObj.h>
#include <iostream>
#include <string>


namespace PrivilegeTest {

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

    //关闭句柄
#define SafeCloseHandle(Handle) { if(Handle){CloseHandle(Handle);Handle=NULL;} }

    bool IsUserAdmin() {
        // Determine if the user is part of the adminstators group. This will return
        // true in case of XP and 2K if the user belongs to admin group. In case of
        // Vista, it only returns true if the admin is running elevated.
        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        PSID administrators_group = NULL;
        BOOL result = ::AllocateAndInitializeSid(&nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &administrators_group);
        if (result) {
            if (!::CheckTokenMembership(NULL, administrators_group, &result)) {
                result = false;
            }
            ::FreeSid(administrators_group);
        }
        return !!result;
    }

    // from https://blog.csdn.net/chenlycly/article/details/45419259/
    BOOL IsRunasAdmin() {
        BOOL bElevated = FALSE;
        HANDLE hToken = NULL;

        // Get current process token
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return FALSE;

        TOKEN_ELEVATION tokenEle;
        DWORD dwRetLen = 0;

        // Retrieve token elevation information
        if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen)) {
            if (dwRetLen == sizeof(tokenEle)) {
                bElevated = tokenEle.TokenIsElevated;
            }
        }

        CloseHandle(hToken);
        return bElevated;
    }


    //获取TokenElevationType
    TOKEN_ELEVATION_TYPE GetProcessTokenElevationTypeStaus(DWORD ProcessId) {
        HANDLE ProcessHandle = NULL;
        HANDLE TokenHandle = NULL;
        static TOKEN_ELEVATION_TYPE TokenElevationTypeStaus = TokenElevationTypeDefault;
        NTSTATUS status;
        static ULONG ReturnLength = sizeof(TOKEN_ELEVATION_TYPE);
        typedef  NTSTATUS(NTAPI *fnZwQueryInformationToken) (HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
        static fnZwQueryInformationToken pZwQueryInformationToken = (fnZwQueryInformationToken)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwQueryInformationToken");

        do {
            ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
            if (ProcessHandle == NULL)break;

            //打开进程令牌  
            if (!OpenProcessToken(ProcessHandle, TOKEN_QUERY, &TokenHandle))
                break;


            status = pZwQueryInformationToken(TokenHandle, TokenElevationType, &TokenElevationTypeStaus, ReturnLength, &ReturnLength);
            if (!NT_SUCCESS(status)) {
                break;
            }
            else {
                printf("%d\n", TokenElevationTypeStaus);
            }

        } while (FALSE);


        SafeCloseHandle(TokenHandle);
        SafeCloseHandle(ProcessHandle);
        return TokenElevationTypeStaus;
    }

    // from https://blog.csdn.net/chenlycly/article/details/45419259/
    BOOL GetProcessElevation(TOKEN_ELEVATION_TYPE* pElevationType, BOOL* pIsAdmin) {
        HANDLE hToken = NULL;
        DWORD dwSize;

        // Get current process token
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return(FALSE);

        BOOL bResult = FALSE;

        // Retrieve elevation type information 
        if (GetTokenInformation(hToken, TokenElevationType,
            pElevationType, sizeof(TOKEN_ELEVATION_TYPE), &dwSize)) {
            // Create the SID corresponding to the Administrators group
            byte adminSID[SECURITY_MAX_SID_SIZE];
            dwSize = sizeof(adminSID);
            CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID,
                &dwSize);

            if (*pElevationType == TokenElevationTypeLimited) {
                // Get handle to linked token (will have one if we are lua)
                HANDLE hUnfilteredToken = NULL;
                GetTokenInformation(hToken, TokenLinkedToken, (VOID*)
                    &hUnfilteredToken, sizeof(HANDLE), &dwSize);

                // Check if this original token contains admin SID
                if (CheckTokenMembership(hUnfilteredToken, &adminSID, pIsAdmin)) {
                    bResult = TRUE;
                }

                // Don't forget to close the unfiltered token
                CloseHandle(hUnfilteredToken);
            }
            else {
                *pIsAdmin = IsUserAnAdmin();
                bResult = TRUE;
            }
        }

        // Don't forget to close the process token
        CloseHandle(hToken);

        return(bResult);
    }

    BOOL IsRunasAdmin(DWORD ProcessId) {
        BOOL bElevated = FALSE;
        HANDLE hToken = NULL;

        //CString strTip;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
        if (hProcess == NULL) {
            printf("hProcess 不存在");
            return false;
        }

        // Get target process token
        if (!OpenProcessToken(hProcess/*GetCurrentProcess()*/, TOKEN_QUERY, &hToken)) {
            /*        strTip.Format(_T("OpenProcessToken failed, GetLastError: %d"), GetLastError());
                    AfxMessageBox(strTip);*/
            return FALSE;
        }

        TOKEN_ELEVATION tokenEle;
        DWORD dwRetLen = 0;

        // Retrieve token elevation information
        if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen)) {
            if (dwRetLen == sizeof(tokenEle)) {
                bElevated = tokenEle.TokenIsElevated;
            }
        }
        else {
            //strTip.Format(_T("GetTokenInformation failed, GetLastError: %d"), GetLastError());
            //AfxMessageBox(strTip);
        }

        CloseHandle(hToken);
        return bElevated;
    }
}

int main(int argc, char *argv[]) {
    
    if (argc == 2)
    {
        int pid = std::stoi(argv[1]);
        std::cout << "pid : "<< pid <<" IsRunasAdmin : " << PrivilegeTest::IsRunasAdmin(pid) << std::endl;
        return 0;
    }
    std::cout << "IsUserAdmin : " << PrivilegeTest::IsUserAdmin() << std::endl;
    std::cout << "IsRunasAdmin : " << PrivilegeTest::IsRunasAdmin() << std::endl;

    TOKEN_ELEVATION_TYPE token_elevation_type = PrivilegeTest::GetProcessTokenElevationTypeStaus(GetCurrentProcessId());
    BOOL isAdmin = FALSE;
    PrivilegeTest::GetProcessElevation(&token_elevation_type, &isAdmin);

    std::cout << "GetProcessElevation : " << isAdmin << std::endl;
    std::cout << "IsUserAnAdmin : " << ::IsUserAnAdmin() << std::endl;

    if (!::IsUserAnAdmin())
    {
        auto RunAsAdministrator = [](LPCTSTR strCommand, LPCTSTR strArgs, bool bWaitProcess) {
            SHELLEXECUTEINFO execinfo;
            memset(&execinfo, 0, sizeof(execinfo));
            execinfo.lpFile = strCommand;
            execinfo.cbSize = sizeof(execinfo);
            execinfo.lpVerb = L"runas";
            execinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
            execinfo.nShow = SW_SHOWDEFAULT;
            execinfo.lpParameters = strArgs;

            ShellExecuteEx(&execinfo);

            if (bWaitProcess) {
                WaitForSingleObject(execinfo.hProcess, INFINITE);
            }
        };
        wchar_t szFilePath[MAX_PATH + 1] = { 0 };
        GetModuleFileName(NULL, szFilePath, MAX_PATH);
        std::wcout << szFilePath << std::endl;
        RunAsAdministrator(szFilePath, L"", false);
    }

    system("pause");
    return 0;
}

//Test 结果
/*
win7 管理员用户直接执行           0010   
win7 管理员用户uac提权后执行      1111
win7 标准用户直接执行             0000
win7 标准用户uac提权后执行        1101
winxp 直接运行                   1001
winxp -runas直接运行             1001
*/