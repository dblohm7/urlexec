#include <windows.h>
#include <wininet.h>
#include <objbase.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <shlobj.h>
#include <shtypes.h>

#include <memory>
#include <type_traits>

#include <stdio.h>

#pragma comment(lib, "ole32")
#pragma comment(lib, "shell32")
#pragma comment(lib, "wininet")

static std::unique_ptr<wchar_t[]> DecodeUrl(const wchar_t* aUrl) {
  wchar_t xbuf;
  DWORD bufLen = sizeof(xbuf);
  if (!::InternetCanonicalizeUrlW(aUrl, &xbuf, &bufLen,
                                  ICU_DECODE | ICU_NO_ENCODE) &&
      ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    wprintf(L"InternetCanonicalizeUrl failed with Win32 error %lu\n",
            ::GetLastError());
    return nullptr;
  }

  auto buf = std::make_unique<wchar_t[]>((bufLen + 1) / sizeof(wchar_t));
  if (!buf) {
    wprintf(L"Buffer allocation failed\n");
    return nullptr;
  }

  if (!::InternetCanonicalizeUrlW(aUrl, buf.get(), &bufLen,
                                  ICU_DECODE | ICU_NO_ENCODE)) {
    wprintf(L"InternetCanonicalizeUrl failed with Win32 error %lu\n",
            ::GetLastError());
    return nullptr;
  }

  return buf;
}

struct CoTaskMemFreeDeleter {
  void operator() (void* aPtr) {
    ::CoTaskMemFree(aPtr);
  }
};

using UniquePidl = std::unique_ptr<std::remove_pointer<LPITEMIDLIST>::type,
                                   CoTaskMemFreeDeleter>;

int wmain(int argc, wchar_t* argv[]) {
  if (argc != 2) {
    wprintf(L"Usage: %s <url>\n", argv[0]);
    return 1;
  }

  PROCESS_MITIGATION_IMAGE_LOAD_POLICY pol = {};
  pol.PreferSystem32Images = 1;
  if (!::SetProcessMitigationPolicy(ProcessImageLoadPolicy, &pol,
                                    sizeof(pol))) {
    wprintf(L"SetProcessMitigationPolicy failed with Win32 error %lu\n",
            ::GetLastError());
    return 1;
  }

  auto decoded = DecodeUrl(argv[1]);
  if (!decoded) {
    return 1;
  }

  wprintf(L"Executing \"%s\"\n", decoded.get());

  LPITEMIDLIST pidl = nullptr;
  SFGAOF sfgao;
  HRESULT hr = ::SHParseDisplayName(decoded.get(), nullptr, &pidl, 0, &sfgao);
  if (FAILED(hr)) {
    wprintf(L"SHParseDisplayName failed with HRESULT 0x%08lX\n", hr);
    return 1;
  }

  UniquePidl upidl(pidl);

  SHELLEXECUTEINFOW sei = {sizeof(sei)};
  sei.fMask = SEE_MASK_NOASYNC | SEE_MASK_INVOKEIDLIST;
  sei.lpVerb = L"open";
  sei.nShow = SW_SHOWNORMAL;
  sei.lpIDList = pidl;

  if (!::ShellExecuteExW(&sei)) {
    wprintf(L"ShellExecuteEx failed with Win32 error %lu\n", ::GetLastError());
    return 1;
  }

  return 0;
}

