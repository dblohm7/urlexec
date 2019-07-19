#include <windows.h>
#include <wininet.h>
#include <objbase.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <shlobj.h>
#include <shtypes.h>

#include <memory>

#include <stdio.h>

static std::unique_ptr<wchar_t[]> DecodeUrl(const wchar_t* aUrl) {
  wchar_t xbuf;
  DWORD bufLen = sizeof(xbuf);
  if (!::InternetCanonicalizeUrlW(aUrl, &xbuf, &bufLen,
                                  ICU_DECODE | ICU_NO_ENCODE) &&
      ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return nullptr;
  }

  auto buf = std::make_unique<wchar_t[]>((bufLen + 1) / sizeof(wchar_t));
  if (!buf) {
    return nullptr;
  }

  if (!::InternetCanonicalizeUrlW(aUrl, buf.get(), &bufLen,
                                  ICU_DECODE | ICU_NO_ENCODE)) {
    return nullptr;
  }

  return buf;
}

struct CoTaskMemFreeDeleter {
  void operator() (void* aPtr) {
    ::CoTaskMemFree(aPtr);
  }
};

using UniquePidl = std::unique_ptr<ITEMIDLIST, CoTaskMemFreeDeleter>;

int wmain(int argc, wchar_t* argv[]) {
  if (argc != 2) {
    return 1;
  }

  PROCESS_MITIGATION_IMAGE_LOAD_POLICY pol = {};
  pol.PreferSystem32Images = 1;
  if (!::SetProcessMitigationPolicy(ProcessImageLoadPolicy, &pol, sizeof(pol))) {
    return 1;
  }

  auto decoded = DecodeUrl(argv[1]);
  if (!decoded) {
    return 1;
  }

  wprintf(L"%s\n", decoded.get());

  LPITEMIDLIST pidl = nullptr;
  SFGAOF sfgao;
  HRESULT hr = ::SHParseDisplayName(decoded.get(), nullptr, &pidl, 0, &sfgao);
  if (FAILED(hr)) {
    return 1;
  }

  UniquePidl upidl(pidl);

  SHELLEXECUTEINFOW sei = {sizeof(sei)};
  sei.fMask = SEE_MASK_NOASYNC | SEE_MASK_INVOKEIDLIST;
  sei.lpVerb = L"open";
  sei.nShow = SW_SHOWNORMAL;
  sei.lpIDList = pidl;

  if (!::ShellExecuteExW(&sei)) {
    return 1;
  }

  return 0;
}

