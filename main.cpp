#include <windows.h>
#include "tp_stub.h"
#include "simplebinder.hpp"
#include <errno.h>
#include <string>

#ifdef _DEBUG
#define dm(msg) TVPAddLog(msg)
#else
#define dm(msg)
#endif

// [XXX] 20230618 何故かコンパイルが通らなくなったので暫定対応
// Program Files (x86)/Windows Kits/8.0/Include/um/libloaderapi.h が include されていない？
// セキュリティアップデート関連？　premake の toolset_xp 問題？
#ifndef LOAD_LIBRARY_SEARCH_APPLICATION_DIR
#define LOAD_LIBRARY_SEARCH_APPLICATION_DIR 0x00000200
#define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS    0x00001000
#define LOAD_LIBRARY_SEARCH_SYSTEM32        0x00000800
#define LOAD_LIBRARY_SEARCH_USER_DIRS       0x00000400
typedef PVOID DLL_DIRECTORY_COOKIE;
#endif


static const char *HEX = "0123456789ABCDEF";

struct System
{
	static tjs_error TJS_INTF_METHOD writeRegValue(
		tTJSVariant	*result,
		tjs_int numparams,
		tTJSVariant **param)
	{
		if(numparams < 2)
			return TJS_E_BADPARAMCOUNT;

		// ルートキーを確定
		ttstr		key	= param[0]->AsStringNoAddRef();
		tjs_int		len = key.length();
		ttstr		hkey= "";
		tjs_int		i;
		for(i=0; i<len; i++)
		{
			if(key[i] == '\\')
				break;
			hkey	+= key[i];
		}
		hkey.ToUppserCase();
		dm(hkey);
		HKEY	hKey	= HKEY_CURRENT_USER;
		if(hkey[5] == 'C')
		{
			if(hkey[6] == 'L')
				hKey	= HKEY_CLASSES_ROOT;
			else if(hkey[13] == 'C')
				hKey	= HKEY_CURRENT_CONFIG;
			else if(hkey[23] == 'U')
				hKey	= HKEY_CURRENT_USER;
		}
		else if(hkey[5] == 'L')
			hKey	= HKEY_LOCAL_MACHINE;
		else if(hkey[5] == 'U')
			hKey	= HKEY_USERS;
		else if(hkey[5] == 'P')
			hKey	= HKEY_PERFORMANCE_DATA;
		else if(hkey[5] == 'D')
			hKey	= HKEY_DYN_DATA;

		//	キー名、値名を取り出す
		tjs_int	j;
		for(j=len-1; j>=0; j--)
		{
			if(key[j] == '\\')
				break;
		}
		ttstr	keyname	= "";
		for(i++; i<j; i++)
			keyname	+= key[i];
		ttstr	valname	= "";
		for(j++; j<len; j++)
			valname	+= key[j];
		dm(keyname);
		dm(valname);

		DWORD	dwDisposition;
		LONG	res;
		res	= RegCreateKeyEx(hKey, keyname.c_str(), 0, NULL,
			REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &dwDisposition);
		if(res != ERROR_SUCCESS)
			return TJS_E_FAIL;

		switch(param[1]->Type())
		{
		case tvtString:
			{
				ttstr	value	= param[1]->AsStringNoAddRef();
				res	= RegSetValueEx(hKey, valname.c_str(), 0, REG_SZ,
					(LPBYTE)value.c_str(), (DWORD)value.length()*2+1);
			}
			break;
		case tvtInteger:
			{
				tjs_uint32	value	= (tjs_uint32)param[1]->AsInteger();
				res	= RegSetValueEx(hKey, valname.c_str(), 0, REG_DWORD, (LPBYTE)&value, sizeof(tjs_uint32));
			}
			break;
		}
		RegCloseKey(hKey);

		return TJS_S_OK;
	}

	// System.readEnvValue
	static tjs_error TJS_INTF_METHOD readEnvValue(tTJSVariant *r, tjs_int n, tTJSVariant **p) {
		if (n < 1) return TJS_E_BADPARAMCOUNT;
		if (p[0]->Type() != tvtString) return TJS_E_INVALIDPARAM;
		ttstr name(p[0]->AsStringNoAddRef());
		if (name == TJS_W("")) return TJS_E_INVALIDPARAM;
		if (r) {
			r->Clear();
			DWORD len = ::GetEnvironmentVariableW(name.c_str(), NULL, 0);
			if (!len) return TJS_S_OK;
			
			tjs_char *tmp = new tjs_char[len];
			if (!tmp) return TJS_E_FAIL;
			ZeroMemory(tmp, len);
			DWORD res = ::GetEnvironmentVariableW(name.c_str(), tmp, len);
			//		if (res != len-1) TVPAddImportantLog(TJS_W("環境変数長が一致しません"));
			*r = ttstr(tmp);
			delete[] tmp;
		}
		return TJS_S_OK;
	}

	// System.writeEnvValue
	static tjs_error TJS_INTF_METHOD writeEnvValue(tTJSVariant *r, tjs_int n, tTJSVariant **p) {
		if (n < 2) return TJS_E_BADPARAMCOUNT;
		if (p[0]->Type() != tvtString) return TJS_E_INVALIDPARAM;
		ttstr name(p[0]->AsStringNoAddRef());
		if (name == TJS_W("")) return TJS_E_INVALIDPARAM;
		ttstr value(p[1]->AsStringNoAddRef());
		if (r) {
			r->Clear();
			DWORD len = ::GetEnvironmentVariableW(name.c_str(), NULL, 0);
			if (len >= 0) {
				tjs_char *tmp = new tjs_char[len];
				if (!tmp) return TJS_E_FAIL;
				ZeroMemory(tmp, len);
				::GetEnvironmentVariableW(name.c_str(), tmp, len);
				//		if (res != len-1) TVPAddImportantLog(TJS_W("環境変数長が一致しません"));
				*r = ttstr(tmp);
				delete[] tmp;
			}
		}
		::SetEnvironmentVariableW(name.c_str(), value.c_str());
		return TJS_S_OK;
	}
	
	// System.expandEnvString
	static tjs_error TJS_INTF_METHOD expandEnvString(tTJSVariant *r, tjs_int n, tTJSVariant **p) {
		if (n < 1) return TJS_E_BADPARAMCOUNT;
		if (r) {
			ttstr src(p[0]->AsStringNoAddRef());
			r->Clear();
			DWORD len = ::ExpandEnvironmentStrings(src.c_str(), NULL, 0);
			if (!len) return TJS_E_FAIL;
			
			tjs_char *tmp = new tjs_char[len];
			if (!tmp) return TJS_E_FAIL;
			ZeroMemory(tmp, len);
			DWORD res = ::ExpandEnvironmentStrings(src.c_str(), tmp, len);
			//		if (res != len) TVPAddImportantLog(TJS_W("展開長が一致しません"));
			*r = ttstr(tmp);
			delete[] tmp;
		}
		return TJS_S_OK;
	}

	// urlencode処理
	static tjs_error TJS_INTF_METHOD urlencode(tTJSVariant *result,
											   tjs_int numparams,
											   tTJSVariant **param) {
		if (numparams > 0 && result) {
			bool utf8 = !(numparams> 1 && (int)*param[1] == 0);
			ttstr str = *param[0];
			tjs_int len;
			char *dat;
			if (utf8) {
				const tjs_char *s = str.c_str();
				len = TVPWideCharToUtf8String(s, NULL);
				dat = new char [len+1];
				try {
					TVPWideCharToUtf8String(s, dat);
					dat[len] = '\0';
				}
				catch(...)	{
					delete [] dat;
					throw;
				}
			} else {
				len = str.GetNarrowStrLen();
				dat = new char[len+1];
				try {
					str.ToNarrowStr(dat, len+1);
				}
				catch(...)	{
					delete [] dat;
					throw;
				} 
				delete [] dat;
			}
			ttstr os;
			for (int i=0; i<len; i++) {
				char c = dat[i];
				if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
					(c >= '0' && c <= '9') ||
					c == '-' || c == '_' || c == '.' || c == '~') {
					os += c;
				} else {
					os += (tjs_char) '%';
					os += (tjs_char) HEX[(c >> 4) & 0x0f];
					os += (tjs_char) HEX[c & 0x0f];
				}
			}
			*result = os;
			delete [] dat;
		}
		return TJS_S_OK;
	}

	
	// urldecode処理
	static tjs_error TJS_INTF_METHOD urldecode(tTJSVariant *result,
											   tjs_int numparams,
											   tTJSVariant **param) {

		if (numparams > 0 && result) {
			bool utf8 = !(numparams> 1 && (int)*param[1] == 0);
			ttstr str = *param[0];
			tjs_int len = str.length();
			std::string os;
			for (int i=0;i<len;i++) {
				int ch = str[i];
				if (ch > 0xff) {
					return TJS_E_INVALIDPARAM;
				}
				if (ch == '%') {
					if (i + 2 >= len) {
						return TJS_E_INVALIDPARAM;
					}
					char buf[3];
					buf[0] = (char)str[i+1];
					buf[1] = (char)str[i+2];
					buf[2] = '\0';
					long n = strtol(buf, NULL, 16);
					if (errno == ERANGE) {
						return TJS_E_INVALIDPARAM;
					}
					os += (char)n;
					i+=2;
				} else {
					os += (char)ch;
				}
			}
			if (utf8) {
				const char *s = os.c_str();
				tjs_int len = TVPUtf8ToWideCharString(s, NULL);
				if (len > 0) {
					tjs_char *dat = new tjs_char[len+1];
					try {
						TVPUtf8ToWideCharString(s, dat);
						dat[len] = TJS_W('\0');
					}
					catch(...) {
						delete [] dat;
						throw;
					}
					*result = ttstr(dat);
					delete [] dat;
				}				
			} else {
				*result = ttstr(os.c_str());
			}
		}
		return TJS_S_OK;
	}

	// TVPGetAboutStringラッパー
	static tjs_error TJS_INTF_METHOD getAboutString(tTJSVariant *r) {
		if (r) {
			ttstr const str(TVPGetAboutString());
			*r = str;
		}
		return TJS_S_OK;
	}

	
	// はいいいえの確認
	static tjs_error TJS_INTF_METHOD confirm(tTJSVariant *result,
											 tjs_int numparams,
											 tTJSVariant **param) {
		if (numparams < 1) return TJS_E_BADPARAMCOUNT;
		ttstr message = *param[0];
		ttstr caption;
		HWND parent = ::TVPGetApplicationWindowHandle();
		if (numparams > 2) {
			iTJSDispatch2 *window = param[2]->AsObjectNoAddRef();
			if (window->IsInstanceOf(0, NULL, NULL, L"Window", window) != TJS_S_TRUE) {
				TVPThrowExceptionMessage(L"InvalidObject");
			}
			tTJSVariant val;
			window->PropGet(0, TJS_W("HWND"), NULL, &val, window);
			parent = reinterpret_cast<HWND>((tjs_intptr_t)(val));
		}
		if (numparams > 1) {
			caption = *param[1];
		}
		int ret = ::MessageBox(parent, message.c_str(), caption.c_str(), MB_YESNO);
		if (result) {
			*result = (ret == IDYES);
		}
		return TJS_S_OK;
	}

	// Mutexが消えるのを待つ
	static tjs_error TJS_INTF_METHOD waitForAppLock(tTJSVariant *result,
													tjs_int numparams,
													tTJSVariant **param) {
		DWORD timeout = 0;
		if (numparams < 1) return TJS_E_BADPARAMCOUNT;
		if (numparams >= 2) timeout = (DWORD)param[1]->AsInteger();
		ttstr key(param[0]->AsStringNoAddRef());

		int status = 0;
		HANDLE mutex = ::OpenMutex(SYNCHRONIZE, FALSE, key.c_str());
		if (   mutex != NULL) {
			DWORD r = ::WaitForSingleObject(mutex, timeout);
			::CloseHandle(mutex);
			switch (r) {
			case WAIT_ABANDONED:
			case WAIT_OBJECT_0: status = 0; break;
			case WAIT_TIMEOUT:  status = 1; break;
			case WAIT_FAILED:
			default: status = -1; break;
			}
		}
		if (result) {
			if (status < 0) result->Clear();
			else *result = !status;
		}
		return TJS_S_OK;
	}

	template <typename T>
	static T GetDllProcAddress(const WCHAR *dll, const char *proc, DWORD flags = GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, bool autoload = false) {
		HMODULE module = NULL;
		if (!::GetModuleHandleExW(flags, dll, &module)) {
			if (autoload) module = ::LoadLibraryW(dll);
			if (!module) return NULL;
		}
		return reinterpret_cast<T>(::GetProcAddress(module, proc));
	}

	// SetThreadDpiAwarenessContextラッパー
	static tjs_error setThreadDpiAwarenessContext(tTJSVariant *r, tTJSVariant *vcontext) {
		static bool lastFailed = false;
		if (r) r->Clear();
		if (lastFailed || !vcontext) return TJS_S_OK;

		typedef HANDLE (WINAPI *SetThreadDpiAwarenessContextT)(HANDLE context);
		static SetThreadDpiAwarenessContextT proc = GetDllProcAddress<SetThreadDpiAwarenessContextT>(L"user32.dll", "SetThreadDpiAwarenessContext");

		if (!proc) {
			TVPAddImportantLog(TJS_W("SetThreadDpiAwarenessContext not found."));
			lastFailed = true;
			return TJS_S_OK;
		}

		tjs_intptr_t const result = (tjs_intptr_t)(proc((HANDLE)(tjs_intptr_t)(tTVInteger)*vcontext));
		if (r) *r = result;
		return TJS_S_OK;
	}

	static tjs_error getOSVersion(tTJSVariant *r);

	static tjs_error TJS_INTF_METHOD getKnownFolderPath(tTJSVariant *result,
														tjs_int numparams,
														tTJSVariant **param);

	// TVPProcessApplicationMessagesラッパー
	static tjs_error TJS_INTF_METHOD processApplicationMessages(tTJSVariant *r) {
		if (r) r->Clear();
		TVPProcessApplicationMessages();
		return TJS_S_OK;
	}
	// TVPHandleApplicationMessageラッパー
	static tjs_error TJS_INTF_METHOD handleApplicationMessage(tTJSVariant *r) {
		if (r) r->Clear();
		TVPHandleApplicationMessage();
		return TJS_S_OK;
	}

	static tjs_error setDefaultDllDirectories(tTJSVariant *r, tTJSVariant *vflags) {
		typedef BOOL (WINAPI *SetDefaultDllDirectoriesT)(DWORD);
		static SetDefaultDllDirectoriesT proc = GetDllProcAddress<SetDefaultDllDirectoriesT>(L"kernel32.dll", "SetDefaultDllDirectories");
		bool result = false;
		if (proc) {
			DWORD const flags = (DWORD)(tTVInteger)*vflags;
			BOOL s = (*proc)(flags);
			result = (s != FALSE);
		}
		if (r) *r = result ? 1 : 0;
		return TJS_S_OK;
	}
	static tjs_error addDllDirectory(tTJSVariant *r, tTJSVariant *vpath) {
		typedef DLL_DIRECTORY_COOKIE (WINAPI *AddDllDirectoryT)(PCWSTR);
		static AddDllDirectoryT proc = GetDllProcAddress<AddDllDirectoryT>(L"kernel32.dll", "AddDllDirectory");
		tTVInteger result = 0;
		if (proc) {
			ttstr const path(*vpath);
			result = reinterpret_cast<tTVInteger>((*proc)(path.c_str()));
		}
		if (r) *r = result;
		return TJS_S_OK;
	}
	static tjs_error removeDllDirectory(tTJSVariant *r, tTJSVariant *vcookie) {
		typedef BOOL (WINAPI *RemoveDllDirectoryT)(DLL_DIRECTORY_COOKIE);
		static RemoveDllDirectoryT proc = GetDllProcAddress<RemoveDllDirectoryT>(L"kernel32.dll", "RemoveDllDirectory");
		bool result = false;
		if (proc) {
			DLL_DIRECTORY_COOKIE const cookie = reinterpret_cast<DLL_DIRECTORY_COOKIE>(vcookie->AsInteger());
			BOOL s = (*proc)(cookie);
			result = (s != FALSE);
		}
		if (r) *r = result ? 1 : 0;
		return TJS_S_OK;
	}
};


extern "C" typedef NTSTATUS (NTAPI *RtlGetVersionProc)(_Out_  PRTL_OSVERSIONINFOEXW lpVersionInformation);
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif
void SetDicValue(iTJSDispatch2 *dic, const tjs_char *key, const ttstr &val) {
	tTJSVariant v(val);
	dic->PropSet(TJS_MEMBERENSURE, key, NULL, &v, dic);
}
void SetDicValue(iTJSDispatch2 *dic, const tjs_char *key, tTVInteger val) {
	tTJSVariant v(val);
	dic->PropSet(TJS_MEMBERENSURE, key, NULL, &v, dic);
}
tjs_error System::getOSVersion(tTJSVariant *r)
{
	HMODULE ntdll = NULL;
	if (r) r->Clear();
	RtlGetVersionProc get = GetDllProcAddress<RtlGetVersionProc>(L"ntdll", "RtlGetVersion");
	if (get) {
		RTL_OSVERSIONINFOEXW ver;
		::ZeroMemory(&ver, sizeof(ver));
		ver.dwOSVersionInfoSize = sizeof(ver);
		if (get(&ver) == STATUS_SUCCESS) {
			iTJSDispatch2 *dic = TJSCreateDictionaryObject();
			if (dic) {
				SetDicValue(dic, TJS_W("major"),    ver.dwMajorVersion);
				SetDicValue(dic, TJS_W("minor"),    ver.dwMinorVersion);
				SetDicValue(dic, TJS_W("build"),    ver.dwBuildNumber);
				SetDicValue(dic, TJS_W("platform"), ver.dwPlatformId);
				SetDicValue(dic, TJS_W("spmajor"),  ver.wServicePackMajor);
				SetDicValue(dic, TJS_W("spminor"),  ver.wServicePackMinor);
				SetDicValue(dic, TJS_W("servicepack"), ttstr(ver.szCSDVersion));
				SetDicValue(dic, TJS_W("suite"),    ver.wSuiteMask);
				SetDicValue(dic, TJS_W("type"),     ver.wProductType);
				if (r) *r = tTJSVariant(dic, dic);
				dic->Release();
			}
		}
	}
	return TJS_S_OK;
}

#include <shlobj.h>
#include <KnownFolders.h>
#define LIST_KNOWN_FOLDER(tag) { # tag, & FOLDERID_ ## tag }
static const GUID CustomFolderID_Video_Captures = {
	0xEDC0FE71, 0x98D8, 0x4F4A, { 0xB9, 0x20, 0xC8, 0xDC, 0x13, 0x3C, 0xB1, 0x65 }
};
static struct StringKnownFilders {
	const char *name;
	const GUID *guid;
} KnownFolderList[] = {
//	LIST_KNOWN_FOLDER(NetworkFolder),
//	LIST_KNOWN_FOLDER(ComputerFolder),
//	LIST_KNOWN_FOLDER(InternetFolder),
//	LIST_KNOWN_FOLDER(ControlPanelFolder),
//	LIST_KNOWN_FOLDER(PrintersFolder),
//	LIST_KNOWN_FOLDER(SyncManagerFolder),
//	LIST_KNOWN_FOLDER(SyncSetupFolder),
//	LIST_KNOWN_FOLDER(ConflictFolder),
//	LIST_KNOWN_FOLDER(SyncResultsFolder),
//	LIST_KNOWN_FOLDER(RecycleBinFolder),
//	LIST_KNOWN_FOLDER(ConnectionsFolder),
	LIST_KNOWN_FOLDER(Fonts),
	LIST_KNOWN_FOLDER(Desktop),
	LIST_KNOWN_FOLDER(Startup),
	LIST_KNOWN_FOLDER(Programs),
	LIST_KNOWN_FOLDER(StartMenu),
	LIST_KNOWN_FOLDER(Recent),
	LIST_KNOWN_FOLDER(SendTo),
	LIST_KNOWN_FOLDER(Documents),
	LIST_KNOWN_FOLDER(Favorites),
	LIST_KNOWN_FOLDER(NetHood),
	LIST_KNOWN_FOLDER(PrintHood),
	LIST_KNOWN_FOLDER(Templates),
	LIST_KNOWN_FOLDER(CommonStartup),
	LIST_KNOWN_FOLDER(CommonPrograms),
	LIST_KNOWN_FOLDER(CommonStartMenu),
	LIST_KNOWN_FOLDER(PublicDesktop),
	LIST_KNOWN_FOLDER(ProgramData),
	LIST_KNOWN_FOLDER(CommonTemplates),
	LIST_KNOWN_FOLDER(PublicDocuments),
	LIST_KNOWN_FOLDER(RoamingAppData),
	LIST_KNOWN_FOLDER(LocalAppData),
	LIST_KNOWN_FOLDER(LocalAppDataLow),
	LIST_KNOWN_FOLDER(InternetCache),
	LIST_KNOWN_FOLDER(Cookies),
	LIST_KNOWN_FOLDER(History),
	LIST_KNOWN_FOLDER(System),
	LIST_KNOWN_FOLDER(SystemX86),
	LIST_KNOWN_FOLDER(Windows),
	LIST_KNOWN_FOLDER(Profile),
	LIST_KNOWN_FOLDER(Pictures),
	LIST_KNOWN_FOLDER(ProgramFilesX86),
	LIST_KNOWN_FOLDER(ProgramFilesCommonX86),
	LIST_KNOWN_FOLDER(ProgramFilesX64),
	LIST_KNOWN_FOLDER(ProgramFilesCommonX64),
	LIST_KNOWN_FOLDER(ProgramFiles),
	LIST_KNOWN_FOLDER(ProgramFilesCommon),
	LIST_KNOWN_FOLDER(AdminTools),
	LIST_KNOWN_FOLDER(CommonAdminTools),
	LIST_KNOWN_FOLDER(Music),
	LIST_KNOWN_FOLDER(Videos),
	LIST_KNOWN_FOLDER(PublicPictures),
	LIST_KNOWN_FOLDER(PublicMusic),
	LIST_KNOWN_FOLDER(PublicVideos),
	LIST_KNOWN_FOLDER(ResourceDir),
	LIST_KNOWN_FOLDER(LocalizedResourcesDir),
	LIST_KNOWN_FOLDER(CommonOEMLinks),
	LIST_KNOWN_FOLDER(CDBurning),
	LIST_KNOWN_FOLDER(UserProfiles),
	LIST_KNOWN_FOLDER(Playlists),
	LIST_KNOWN_FOLDER(SamplePlaylists),
	LIST_KNOWN_FOLDER(SampleMusic),
	LIST_KNOWN_FOLDER(SamplePictures),
	LIST_KNOWN_FOLDER(SampleVideos),
	LIST_KNOWN_FOLDER(PhotoAlbums),
	LIST_KNOWN_FOLDER(Public),
//	LIST_KNOWN_FOLDER(ChangeRemovePrograms),
//	LIST_KNOWN_FOLDER(AppUpdates),
//	LIST_KNOWN_FOLDER(AddNewPrograms),
	LIST_KNOWN_FOLDER(Downloads),
	LIST_KNOWN_FOLDER(PublicDownloads),
	LIST_KNOWN_FOLDER(SavedSearches),
	LIST_KNOWN_FOLDER(QuickLaunch),
	LIST_KNOWN_FOLDER(Contacts),
	LIST_KNOWN_FOLDER(SidebarParts),
	LIST_KNOWN_FOLDER(SidebarDefaultParts),
//	LIST_KNOWN_FOLDER(TreeProperties), // Not used in Windows Vista. Unsupported as of Windows 7.
	LIST_KNOWN_FOLDER(PublicGameTasks),
	LIST_KNOWN_FOLDER(GameTasks),
	LIST_KNOWN_FOLDER(SavedGames),
//	LIST_KNOWN_FOLDER(Games), // [!Note] deprecated in Windows 10, version 1803 and later versions
//	LIST_KNOWN_FOLDER(RecordedTV), // Not used. This value is undefined as of Windows 7.
//	LIST_KNOWN_FOLDER(SEARCH_MAPI),
//	LIST_KNOWN_FOLDER(SEARCH_CSC),
	LIST_KNOWN_FOLDER(Links),
//	LIST_KNOWN_FOLDER(UsersFiles),
//	LIST_KNOWN_FOLDER(SearchHome),
	LIST_KNOWN_FOLDER(OriginalImages),

	{ "Captures", &CustomFolderID_Video_Captures }, // [XXX] for GameBar Captures (%USERPROFILE%\Video\Captures)
	{ 0, 0 }
};

extern "C" typedef HRESULT (WINAPI *SHGetKnownFolderPathProc)(REFKNOWNFOLDERID, DWORD, HANDLE, PWSTR*);
tjs_error TJS_INTF_METHOD System::getKnownFolderPath(tTJSVariant *result,
													 tjs_int numparams,
													 tTJSVariant **param)
{
	if (numparams < 1) return TJS_E_BADPARAMCOUNT;
	GUID guid;
	const GUID *refguid = NULL;
	DWORD flags = TJS_PARAM_EXIST(1) ? (DWORD)param[1]->AsInteger() : 0;
	switch (param[0]->Type()) {
	case tvtOctet: {
		tTJSVariantOctet *oct = param[0]->AsOctetNoAddRef();
		if (oct && oct->GetLength() == 16) {
			// Octet -> GUID
			const tjs_uint8 *data = oct->GetData();
			guid.Data1 = data[3] | (data[2]<<8) | (data[1]<<16) | (data[0]<<24);
			guid.Data2 = data[5] | (data[4]<<8);
			guid.Data3 = data[7] | (data[6]<<8);
			guid.Data4[0] = data[8];
			guid.Data4[1] = data[9];
			guid.Data4[2] = data[10];
			guid.Data4[3] = data[11];
			guid.Data4[4] = data[12];
			guid.Data4[5] = data[13];
			guid.Data4[6] = data[14];
			guid.Data4[7] = data[15];
			refguid = &guid;
		} else {
			return TJS_E_INVALIDPARAM;
		}
	} break;
	case tvtString:
		// search known folder id
		ttstr target(*param[0]);
		for (StringKnownFilders *table = KnownFolderList; table->name; ++table) {
			ttstr name(table->name);
			if (name == target) {
				refguid = table->guid;
				break;
			}
		}
		if (!refguid) {
			ttstr mes(TVPFormatMessage(TJS_W("Unknown FOLDERID : %1"), target));
			TVPAddImportantLog(mes);
		}
		break;
	}
	if (result) result->Clear();

	static SHGetKnownFolderPathProc procSHGetKnownFolderPath = NULL;
	if(!procSHGetKnownFolderPath) {
		procSHGetKnownFolderPath = GetDllProcAddress<SHGetKnownFolderPathProc>(L"SHELL32.DLL", "SHGetKnownFolderPath");
	}
	if (procSHGetKnownFolderPath && refguid) {
		ttstr path;
		PWSTR ppszPath = NULL;
		if (SUCCEEDED(procSHGetKnownFolderPath(*refguid, flags, NULL, &ppszPath))) {
			path = ttstr(ppszPath);
			::CoTaskMemFree(ppszPath);
		}
		if (result) *result = path;
	}
	return TJS_S_OK;
}

static bool SystemExEntry(bool entry) {
	return (SimpleBinder::BindUtil(TJS_W("System"), entry)
			.Function(TJS_W("writeRegValue"),       &System::writeRegValue)
			.Function(TJS_W("readEnvValue"),        &System::readEnvValue)
			.Function(TJS_W("writeEnvValue"),       &System::writeEnvValue)
			.Function(TJS_W("expandEnvString"),     &System::expandEnvString)
			.Function(TJS_W("urlencode"),           &System::urlencode)
			.Function(TJS_W("urldecode"),           &System::urldecode)
			.Function(TJS_W("getAboutString"),      &System::getAboutString)
			.Function(TJS_W("confirm"),             &System::confirm)
			.Function(TJS_W("waitForAppLock"),      &System::waitForAppLock)

			.Function(TJS_W("setDpiAwareness"),     &System::setThreadDpiAwarenessContext)
			.Variant(TJS_W("dacUnaware"),           -1) // DPI_AWARENESS_CONTEXT_UNAWARE
			.Variant(TJS_W("dacSystemAware"),       -2) // DPI_AWARENESS_CONTEXT_SYSTEM_AWARE
			.Variant(TJS_W("dacPerMonitorAware"),   -3) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE
			.Variant(TJS_W("dacPerMonitorAwareV2"), -4) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 // (Creators Update or later)
			.Variant(TJS_W("dacUnawareGdiScaled"),  -5) // DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED    // (October 2018 update or later)

			.Function(TJS_W("getOSVersion"),        &System::getOSVersion)
			.Function(TJS_W("getKnownFolderPath"),  &System::getKnownFolderPath)
			.Function(TJS_W("processApplicationMessages"),  &System::processApplicationMessages)
			.Function(TJS_W("handleApplicationMessage"),    &System::handleApplicationMessage)

			.Function(TJS_W("setDefaultDllDirectories"), &System::setDefaultDllDirectories)
			.Variant(TJS_W("llsApplicationDir"), LOAD_LIBRARY_SEARCH_APPLICATION_DIR) // 0x00000200
			.Variant(TJS_W("llsDefaultDirs"),    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)    // 0x00001000
			.Variant(TJS_W("llsSystem32"),       LOAD_LIBRARY_SEARCH_SYSTEM32)        // 0x00000800
			.Variant(TJS_W("llsUserDirs"),       LOAD_LIBRARY_SEARCH_USER_DIRS)       // 0x00000400
			.Function(TJS_W("addDllDirectory"),    &System::addDllDirectory)
			.Function(TJS_W("removeDllDirectory"), &System::removeDllDirectory)

			.IsValid());
}

#ifndef SYSTEMEX_NO_V2LINK
bool onV2Link()   { return SystemExEntry(true);  }
bool onV2Unlink() { return SystemExEntry(false); }
#endif
