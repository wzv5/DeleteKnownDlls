#include <windows.h>
#include <tchar.h>
#include <shlwapi.h>
#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

void EnableTakeOwnershipPrivilege()
{
	HANDLE hToken = NULL;
	LUID luid;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_TAKE_OWNERSHIP_NAME, &luid);
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	// 除了SeTakeOwnershipPrivilege权限外，还需要SeRestorePrivilege权限
	// 才能还原所有者为“NT SERVICE\TrustedInstaller”（KnownDlls的原始所有者）
	LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &luid);
	tp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	CloseHandle(hToken);
}

DWORD SecurityRegDeleteValue(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName)
{
	DWORD ret, ret2;
	HKEY hk;
	DWORD dwSize = 0;
	PSECURITY_DESCRIPTOR pOldSD = NULL;
	PSECURITY_DESCRIPTOR pNewSD = NULL;
	PSID pAdminSID = NULL;
	PACL pNewDACL = NULL;
	PEXPLICIT_ACCESS pEA = NULL;
	BOOL bPresent = FALSE, bDefaulted = FALSE;
	do
	{
		// 打开注册表键，先修改所有者
		ret = RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ | READ_CONTROL | WRITE_OWNER, &hk);
		if (ret != ERROR_SUCCESS)
		{
			break;
		}
		
		// 获取原始安全属性
		RegGetKeySecurity(hk, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, NULL, &dwSize);
		pOldSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSize);
		ret = RegGetKeySecurity(hk, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, pOldSD, &dwSize);
		if (ret != ERROR_SUCCESS)
		{
			break;
		}

		// 创建新的空安全属性对象，用于修改所有者
		pNewSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
		if (!InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION))
		{
			ret = GetLastError();
			break;
		}

		// 获取Administrators的SID
		SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
		if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
			SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0,
			&pAdminSID
			))
		{
			ret = GetLastError();
			break;
		}
		
		// 修改注册表键的所有者为Administrators
		if (!SetSecurityDescriptorOwner(pNewSD, pAdminSID, FALSE))
		{
			ret = GetLastError();
			break;
		}
		ret = RegSetKeySecurity(hk, OWNER_SECURITY_INFORMATION, pNewSD);
		if (ret != ERROR_SUCCESS)
		{
			break;
		}
		
		// 关闭注册表句柄，并以写入ACL的权限重新打开
		RegCloseKey(hk);
		ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpSubKey, 0, KEY_READ | WRITE_OWNER | WRITE_DAC, &hk);
		if (ret != ERROR_SUCCESS)
		{
			break;
		}

		// 设置新安全属性的ACL，赋予Administrators所有权限
		pEA = (PEXPLICIT_ACCESS)LocalAlloc(LPTR, sizeof(EXPLICIT_ACCESS));
		pEA->grfAccessPermissions = KEY_ALL_ACCESS;
		pEA->grfAccessMode = SET_ACCESS;
		pEA->grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
		pEA->Trustee.TrusteeForm = TRUSTEE_IS_SID;
		pEA->Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		pEA->Trustee.ptstrName = (LPTSTR)pAdminSID;
		ret = SetEntriesInAcl(1, pEA, NULL, &pNewDACL);
		if (ret != ERROR_SUCCESS)
		{
			break;
		}
		if (!SetSecurityDescriptorDacl(pNewSD, TRUE, pNewDACL, FALSE))
		{
			ret = GetLastError();
			break;
		}

		// 设置注册表键的ACL
		ret = RegSetKeySecurity(hk, DACL_SECURITY_INFORMATION, pNewSD);
		if (ret != ERROR_SUCCESS)
		{
			break;
		}

		// 再次关闭注册表句柄，并以完整的读写权限重新打开
		// 终于把权限获取完整了，真不容易。。。 _(:3 」∠)_
		RegCloseKey(hk);
		ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpSubKey, 0, KEY_READ | KEY_WRITE | WRITE_OWNER | WRITE_DAC, &hk);
		if (ret != ERROR_SUCCESS)
		{
			break;
		}

		// 准备就绪，开始删除（妈蛋，上面那一大坨代码只是为了这一行做准备）
		// 这里可以弹个框暂停一下，如果此时手动查看注册表权限，会发现所有者是Administrators，拥有完全访问权限
		//MessageBox(NULL, _T("准备就绪，开始删除"), _T(""), MB_ICONINFORMATION);
		ret = RegDeleteValue(hk, lpValueName);
		
		// 还原原始安全属性，分两步走，先还原ACL，再还原所有者，便于判断错误
		ret2 = RegSetKeySecurity(hk, DACL_SECURITY_INFORMATION, pOldSD);
		if (ret2 != ERROR_SUCCESS)
		{
			TCHAR buf[1024];
			wsprintf(buf, _T("还原ACL失败，错误码：%d"), ret2);
			MessageBox(NULL, buf, _T(""), MB_ICONERROR);
		}
		
		// 还原所有者时卡了我2个小时，各种尝试各种失败
		// 最后没办法，打开神器“API Monitor”，对系统自带的icacls.exe进行分析
		// 分析后发现，原来进程还缺一个SeRestorePrivilege权限（我擦什么鬼！msdn根本没提！）
		// 虽然我可以直接设置个System所有者凑合，但总觉得没默认的TrustedInstaller安全
		ret2 = RegSetKeySecurity(hk, OWNER_SECURITY_INFORMATION, pOldSD);
		if (ret2 != ERROR_SUCCESS)
		{
			TCHAR buf[1024];
			wsprintf(buf, _T("还原所有者失败，错误码：%d"), ret2);
			MessageBox(NULL, buf, _T(""), MB_ICONERROR);
		}
		
	} while (false);

	// 清理资源
	if (pOldSD)
		LocalFree(pOldSD);
	if (pNewSD)
		LocalFree(pNewSD);
	if (pAdminSID)
		FreeSid(pAdminSID);
	if (pNewDACL)
		LocalFree(pNewDACL);
	if (pEA)
		LocalFree(pEA);
	return ret;
}

int main()
{
	TCHAR buf[1024];
	LPCTSTR subkey = _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDlls");
	HKEY hk;
	DWORD ret;

	// 提升当前进程权限
	EnableTakeOwnershipPrivilege();

	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hk);
	if (ret == ERROR_SUCCESS)
	{
		TCHAR key[2048];
		TCHAR value[2048];
		DWORD klen = 2048, vlen = 2048, ktype = REG_SZ;
		int n = 0;
		while (RegEnumValue(hk, n, key, &klen, NULL, &ktype, (LPBYTE)value, &vlen) == ERROR_SUCCESS)
		{
			TCHAR akey[] = _T("d3d9.dll");
			if (StrCmpNI(value, akey, _tcslen(akey)) == 0)  // 这个API都有，不查msdn不知道
			{
				wsprintf(buf, _T("发现注册表项：%s，是否删除？"), key);
				if (MessageBox(NULL, buf, _T(""), MB_ICONQUESTION | MB_OKCANCEL) == IDOK)
				{
					ret = SecurityRegDeleteValue(HKEY_LOCAL_MACHINE, subkey, key);
					if (ret == ERROR_SUCCESS)
					{
						MessageBox(NULL, _T("删除成功！"), _T(""), MB_ICONINFORMATION);
					}
					else
					{
						wsprintf(buf, _T("删除失败，错误码：%d"), ret);
						MessageBox(NULL, buf, _T(""), MB_ICONERROR);
					}
				}
			}
			++n;
			klen = 2048;
			vlen = 2048;
			ktype = REG_SZ;
		}
		MessageBox(NULL, _T("运行完毕"), _T(""), MB_ICONINFORMATION);
		RegCloseKey(hk);
	}
	else
	{
		wsprintf(buf, _T("打开注册表失败，错误码：%d"), ret);
		MessageBox(NULL, buf, _T(""), MB_ICONERROR);
	}

	// 由于使用了自定义的main函数来使程序体积最小化，如果不手动调用ExitProcess()，进程就不会自动结束
	ExitProcess(0);
	return 0;
}

