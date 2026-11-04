/* Copyright 2026 the SumatraPDF project authors (see AUTHORS file).
   License: GPLv3 */

#include "utils/BaseUtil.h"
#include "utils/FileUtil.h"
#include "utils/ScopedWin.h"
#include "utils/WinUtil.h"
#include "utils/Dpi.h"
#include "utils/ThreadUtil.h"
#include "utils/UITask.h"
#include "utils/JsonParser.h"
#include "utils/CryptoUtil.h"
#include "utils/WinDynCalls.h"
#include "utils/Log.h"

#include <commctrl.h>
#include <gdiplus.h>

#include "wingui/UIModels.h"
#include "wingui/Layout.h"
#include "wingui/WinGui.h"

#include "Settings.h"
#include "AppSettings.h"
#include "GlobalPrefs.h"
#include "Translations.h"
#include "Theme.h"
#include "FloatingPopupStyle.h"
#include "SumatraPDF.h"
#include "MainWindow.h"
#include "DocController.h"
#include "EngineBase.h"
#include "DisplayModel.h"
#include "Notifications.h"
#include "SumatraConfig.h"
#include "Selection.h"
#include "SelectionToolbar.h"
#include "WindowTab.h"
#include "InlineTranslateLang.h"
#include "InlineTranslate.h"
#include "WordLookup.h"
#include "DarkModeSubclass.h"
#include "AppDialogTheme.h"

#include <bcrypt.h>
#include <wininet.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wininet.lib")

constexpr int kMaxTranslateChars = 4000;
constexpr int kTranslateCacheN = 16;
constexpr int kVolcTimeoutMs = 30 * 1000;

#define kInlineTranslateClassName L"SumatraInlineTranslatePopup"

// ---------------------------------------------------------------------------
// secrets / config

bool InlineTranslateVolcIsConfigured() {
    if (!gGlobalPrefs) {
        return false;
    }
    return !str::IsEmptyOrWhiteSpace(gGlobalPrefs->translateVolcAccessKey) &&
           !str::IsEmptyOrWhiteSpace(gGlobalPrefs->translateVolcSecretKey);
}

void InlineTranslateUnprotectPrefsSecrets(GlobalPrefs* prefs) {
    if (!prefs) {
        return;
    }
    if (char* plain = UnprotectStringDpapi(prefs->translateVolcAccessKey)) {
        str::ReplacePtr(&prefs->translateVolcAccessKey, plain);
    }
    if (char* plain = UnprotectStringDpapi(prefs->translateVolcSecretKey)) {
        str::ReplacePtr(&prefs->translateVolcSecretKey, plain);
    }
}

void InlineTranslateProtectPrefsSecretsForSave(GlobalPrefs* prefs, char** plainAkOut, char** plainSkOut) {
    *plainAkOut = nullptr;
    *plainSkOut = nullptr;
    if (!prefs) {
        return;
    }
    *plainAkOut = prefs->translateVolcAccessKey;
    *plainSkOut = prefs->translateVolcSecretKey;
    if (char* protectedAk = ProtectStringDpapi(prefs->translateVolcAccessKey)) {
        prefs->translateVolcAccessKey = protectedAk;
    } else {
        *plainAkOut = nullptr;
    }
    if (char* protectedSk = ProtectStringDpapi(prefs->translateVolcSecretKey)) {
        prefs->translateVolcSecretKey = protectedSk;
    } else {
        *plainSkOut = nullptr;
    }
}

void InlineTranslateRestorePrefsSecretsAfterSave(GlobalPrefs* prefs, char* plainAk, char* plainSk) {
    if (!prefs) {
        return;
    }
    if (plainAk) {
        str::Free(prefs->translateVolcAccessKey);
        prefs->translateVolcAccessKey = plainAk;
    }
    if (plainSk) {
        str::Free(prefs->translateVolcSecretKey);
        prefs->translateVolcSecretKey = plainSk;
    }
}

// ---------------------------------------------------------------------------
// short translation cache

struct TranslateCacheEntry {
    char* key = nullptr;
    char* translation = nullptr;
};

static TranslateCacheEntry gTranslateCache[kTranslateCacheN];
static int gTranslateCacheNext = 0;
static Mutex gTranslateCacheMutex;

static char* MakeCacheKey(const char* src, const char* target) {
    return str::Format("%s\n%s", src ? src : "", target ? target : "");
}

static char* CacheLookup(const char* src, const char* target) {
    char* key = MakeCacheKey(src, target);
    defer {
        str::Free(key);
    };
    gTranslateCacheMutex.Lock();
    char* hit = nullptr;
    for (int i = 0; i < kTranslateCacheN; i++) {
        if (gTranslateCache[i].key && str::Eq(gTranslateCache[i].key, key)) {
            hit = str::Dup(gTranslateCache[i].translation);
            break;
        }
    }
    gTranslateCacheMutex.Unlock();
    return hit;
}

static void CacheStore(const char* src, const char* target, const char* translation) {
    if (str::IsEmptyOrWhiteSpace(translation)) {
        return;
    }
    char* key = MakeCacheKey(src, target);
    gTranslateCacheMutex.Lock();
    int i = gTranslateCacheNext % kTranslateCacheN;
    gTranslateCacheNext++;
    str::Free(gTranslateCache[i].key);
    str::Free(gTranslateCache[i].translation);
    gTranslateCache[i].key = key;
    gTranslateCache[i].translation = str::Dup(translation);
    gTranslateCacheMutex.Unlock();
}

// ---------------------------------------------------------------------------
// crypto / HTTP

static bool HmacSha256(const void* key, size_t keyLen, const void* data, size_t dataLen, u8 out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    DWORD objLen = 0;
    DWORD cb = 0;
    PUCHAR obj = nullptr;
    if (!BCRYPT_SUCCESS(
            BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        return false;
    }
    if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0))) {
        goto Exit;
    }
    obj = (PUCHAR)malloc(objLen);
    if (!obj) {
        goto Exit;
    }
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, obj, objLen, (PUCHAR)key, (ULONG)keyLen, 0))) {
        goto Exit;
    }
    if (!BCRYPT_SUCCESS(BCryptHashData(hash, (PUCHAR)data, (ULONG)dataLen, 0))) {
        goto Exit;
    }
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, out, 32, 0))) {
        goto Exit;
    }
    ok = true;
Exit:
    if (hash) {
        BCryptDestroyHash(hash);
    }
    if (alg) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    free(obj);
    return ok;
}

static void Sha256Hex(const void* data, size_t dataLen, char outHex[65]) {
    u8 dig[32];
    CalcSHA2Digest(data, (int)dataLen, dig);
    for (int i = 0; i < 32; i++) {
        _snprintf_s(outHex + i * 2, 3, _TRUNCATE, "%02x", dig[i]);
    }
    outHex[64] = 0;
}

static void HexEncode(const u8* dig, int n, char* outHex) {
    for (int i = 0; i < n; i++) {
        _snprintf_s(outHex + i * 2, 3, _TRUNCATE, "%02x", dig[i]);
    }
    outHex[n * 2] = 0;
}

static void AppendJsonEscapedLocal(StrBuilder& out, const char* s) {
    out.AppendChar('"');
    if (s) {
        for (const u8* p = (const u8*)s; *p; p++) {
            u8 c = *p;
            if (c == '"') {
                out.Append("\\\"");
            } else if (c == '\\') {
                out.Append("\\\\");
            } else if (c == '\n') {
                out.Append("\\n");
            } else if (c == '\r') {
                out.Append("\\r");
            } else if (c == '\t') {
                out.Append("\\t");
            } else if (c < 0x20) {
                out.AppendFmt("\\u%04x", c);
            } else {
                out.AppendChar((char)c);
            }
        }
    }
    out.AppendChar('"');
}

struct HttpResult {
    DWORD status = 0;
    StrBuilder body;
};

static bool HttpPostRaw(const char* host, const char* pathAndQuery, const char* headers, const char* body,
                        int timeoutMs, HttpResult& res, char** errOut) {
    *errOut = nullptr;
    HINTERNET hInet =
        InternetOpenA("SumatraPDF-Plus/InlineTranslate", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInet) {
        *errOut = str::Dup("Cannot initialize WinINet.");
        return false;
    }
    HINTERNET hConn =
        InternetConnectA(hInet, host, INTERNET_DEFAULT_HTTPS_PORT, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) {
        InternetCloseHandle(hInet);
        *errOut = str::Format("Cannot connect to '%s'.", host);
        return false;
    }
    DWORD flags = INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE;
    HINTERNET hReq = HttpOpenRequestA(hConn, "POST", pathAndQuery, nullptr, nullptr, nullptr, flags, 0);
    if (!hReq) {
        InternetCloseHandle(hConn);
        InternetCloseHandle(hInet);
        *errOut = str::Dup("Cannot create the HTTP request.");
        return false;
    }
    DWORD connectTimeout = 30 * 1000;
    DWORD recvTimeout = (DWORD)timeoutMs;
    InternetSetOptionA(hReq, INTERNET_OPTION_CONNECT_TIMEOUT, &connectTimeout, sizeof(connectTimeout));
    InternetSetOptionA(hReq, INTERNET_OPTION_SEND_TIMEOUT, &recvTimeout, sizeof(recvTimeout));
    InternetSetOptionA(hReq, INTERNET_OPTION_RECEIVE_TIMEOUT, &recvTimeout, sizeof(recvTimeout));
    bool ok = false;
    if (!HttpSendRequestA(hReq, headers, (DWORD)-1, (LPVOID)body, body ? (DWORD)strlen(body) : 0)) {
        *errOut = str::Format("Network error (WinINet %u).", (unsigned)GetLastError());
        goto Exit;
    }
    {
        DWORD status = 0;
        DWORD len = sizeof(status);
        HttpQueryInfoA(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &len, nullptr);
        res.status = status;
        for (;;) {
            char buf[8192];
            DWORD n = 0;
            if (!InternetReadFile(hReq, buf, sizeof(buf), &n)) {
                *errOut = str::Dup("Failed reading the response.");
                goto Exit;
            }
            if (n == 0) {
                break;
            }
            res.body.Append(buf, n);
        }
        ok = true;
    }
Exit:
    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInet);
    return ok;
}

static bool VolcTranslateText(const char* ak, const char* sk, const char* text, const char* targetLang, char** outText,
                              char** errOut) {
    *outText = nullptr;
    *errOut = nullptr;
    if (str::IsEmptyOrWhiteSpace(ak) || str::IsEmptyOrWhiteSpace(sk)) {
        *errOut = str::Dup("Volcengine keys are not configured.");
        return false;
    }
    const char* host = "translate.volcengineapi.com";
    const char* region = "cn-north-1";
    const char* service = "translate";
    const char* action = "TranslateText";
    const char* version = "2020-06-01";

    SYSTEMTIME st{};
    GetSystemTime(&st);
    char dateStamp[16]{};
    char amzDate[32]{};
    _snprintf_s(dateStamp, _TRUNCATE, "%04d%02d%02d", st.wYear, st.wMonth, st.wDay);
    _snprintf_s(amzDate, _TRUNCATE, "%04d%02d%02dT%02d%02d%02dZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                st.wSecond);

    StrBuilder body;
    body.Append("{\"SourceLanguage\":\"\",\"TargetLanguage\":");
    AppendJsonEscapedLocal(body, targetLang ? targetLang : "zh");
    body.Append(",\"TextList\":[");
    AppendJsonEscapedLocal(body, text ? text : "");
    body.Append("]}");

    char payloadHash[65]{};
    Sha256Hex(body.Get(), body.size(), payloadHash);

    StrBuilder canonical;
    canonical.Append("POST\n/\n");
    canonical.AppendFmt("Action=%s&Version=%s\n", action, version);
    canonical.AppendFmt("content-type:application/json\nhost:%s\nx-content-sha256:%s\nx-date:%s\n\n", host, payloadHash,
                        amzDate);
    canonical.Append("content-type;host;x-content-sha256;x-date\n");
    canonical.Append(payloadHash);

    char canonicalHash[65]{};
    Sha256Hex(canonical.Get(), canonical.size(), canonicalHash);

    TempStr credentialScope = str::FormatTemp("%s/%s/%s/request", dateStamp, region, service);
    StrBuilder stringToSign;
    stringToSign.Append("HMAC-SHA256\n");
    stringToSign.Append(amzDate);
    stringToSign.AppendChar('\n');
    stringToSign.Append(credentialScope);
    stringToSign.AppendChar('\n');
    stringToSign.Append(canonicalHash);

    u8 kDate[32], kRegion[32], kService[32], kSigning[32], signature[32];
    if (!HmacSha256(sk, strlen(sk), dateStamp, strlen(dateStamp), kDate) ||
        !HmacSha256(kDate, 32, region, strlen(region), kRegion) ||
        !HmacSha256(kRegion, 32, service, strlen(service), kService) ||
        !HmacSha256(kService, 32, "request", 7, kSigning) ||
        !HmacSha256(kSigning, 32, stringToSign.Get(), stringToSign.size(), signature)) {
        *errOut = str::Dup("Failed to sign the Volcengine request.");
        return false;
    }
    char sigHex[65]{};
    HexEncode(signature, 32, sigHex);

    TempStr auth = str::FormatTemp(
        "HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature=%s", ak,
        credentialScope, sigHex);

    StrBuilder headers;
    headers.AppendFmt(
        "Content-Type: application/json\r\nHost: %s\r\nX-Date: %s\r\nX-Content-Sha256: %s\r\n"
        "Authorization: %s\r\n",
        host, amzDate, payloadHash, auth);

    TempStr path = str::FormatTemp("/?Action=%s&Version=%s", action, version);
    HttpResult res;
    if (!HttpPostRaw(host, path, headers.Get(), body.Get(), kVolcTimeoutMs, res, errOut)) {
        return false;
    }

    struct TranslationVisitor : json::ValueVisitor {
        StrBuilder translation;
        StrBuilder errCode;
        StrBuilder errMsg;
        bool Visit(const char* pathIn, const char* value, json::Type type) override {
            if (type != json::Type::String) {
                return true;
            }
            if (str::Eq(pathIn, "/TranslationList[0]/Translation") ||
                str::Eq(pathIn, "/TranslationList[0]/translation")) {
                translation.Append(value);
            } else if (str::Eq(pathIn, "/ResponseMetadata/Error/Code")) {
                errCode.Append(value);
            } else if (str::Eq(pathIn, "/ResponseMetadata/Error/Message") || str::Eq(pathIn, "/message")) {
                errMsg.Append(value);
            }
            return true;
        }
    } vis;
    bool parsed = res.body.Get() && json::Parse(res.body.Get(), &vis);
    bool httpOk = res.status >= 200 && res.status < 300;
    if (httpOk && parsed && vis.translation.size() > 0) {
        *outText = str::Dup(vis.translation.Get());
        return true;
    }
    if (vis.errCode.size() > 0 || vis.errMsg.size() > 0) {
        *errOut = str::Format("HTTP %u %s %s", (unsigned)res.status, vis.errCode.size() > 0 ? vis.errCode.Get() : "",
                              vis.errMsg.size() > 0 ? vis.errMsg.Get() : "");
    } else if (!httpOk) {
        *errOut = str::Format("HTTP %u", (unsigned)res.status);
    } else if (!parsed) {
        *errOut = str::Dup("Failed to parse Volcengine response.");
    } else {
        *errOut = str::Dup("Volcengine returned no translation.");
    }
    return false;
}

bool InlineTranslateVolcTest(const char* ak, const char* sk, char** resultOut, char** errOut) {
    return VolcTranslateText(ak, sk, "Hello, world.", "zh", resultOut, errOut);
}

// ---------------------------------------------------------------------------
// selection text

static bool IsAsciiLower(char c) {
    return c >= 'a' && c <= 'z';
}

static bool IsAsciiAlpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// PDF selections are hard-wrapped at line ends. Join wrapped lines so the
// engine sees whole sentences; a blank line stays a paragraph break.
static char* NormalizeSelectionText(const char* s) {
    StrBuilder out;
    for (const char* p = s ? s : ""; *p;) {
        char c = *p;
        if (c != '\r' && c != '\n') {
            out.AppendChar(c == '\t' ? ' ' : c);
            p++;
            continue;
        }
        int nl = 0;
        const char* q = p;
        while (*q == '\r' || *q == '\n' || *q == ' ' || *q == '\t') {
            if (*q == '\n') {
                nl++;
            }
            q++;
        }
        if (!*q) {
            break;
        }
        while (out.size() > 0 && out.LastChar() == ' ') {
            out.RemoveLast();
        }
        if (out.size() > 0) {
            if (nl >= 2) {
                out.Append("\n\n");
            } else {
                char prev = out.LastChar();
                char next = *q;
                if (prev == '-' && IsAsciiLower(next) && out.size() >= 2 && IsAsciiAlpha(out.Get()[out.size() - 2])) {
                    out.RemoveLast();
                } else if ((u8)prev < 0x80 && (u8)next < 0x80) {
                    out.AppendChar(' ');
                }
            }
        }
        p = q;
    }
    char* res = str::Dup(out.size() > 0 ? out.Get() : "");
    str::TrimWSInPlace(res, str::TrimOpt::Both);
    return res;
}

static const char* RoughLangCode(RoughLang lang) {
    switch (lang) {
        case RoughLang::Zh:
            return "zh";
        case RoughLang::En:
            return "en";
        case RoughLang::Ja:
            return "ja";
        case RoughLang::Ko:
            return "ko";
        default:
            return nullptr;
    }
}

// Display name for a translate code in the current UI language.
static const char* LangCodeUiName(const char* code) {
    if (str::IsEmptyOrWhiteSpace(code)) {
        return nullptr;
    }
    if (str::EqI(code, "zh")) {
        return _TRA("Chinese");
    }
    return _TRA(TranslateCodeDisplayName(code));
}

// ---------------------------------------------------------------------------
// popup UI

constexpr UINT_PTR kTransSubclassId = 0x51A9;
constexpr UINT_PTR kCopiedTimerId = 1;
constexpr int kCopiedFlashMs = 1200;

enum class PopupHot {
    None,
    Close,
    Copy,
};

struct InlineTranslatePopup {
    MainWindow* win = nullptr;
    HWND hwnd = nullptr;
    HWND hwndTip = nullptr;
    HWND hwndTrans = nullptr;
    HFONT font = nullptr;
    unsigned fontGeneration = 0;
    HFONT titleFont = nullptr; // owned
    HFONT bodyFont = nullptr;  // owned; translation text, two points above the UI font
    HBRUSH fieldBrush = nullptr;
    char* selection = nullptr;  // normalized
    char* translation = nullptr; // set once a translation arrived
    char* transError = nullptr;
    char* dstCode = nullptr;
    const char* srcCode = nullptr; // static
    bool translating = false;
    bool closing = false;
    bool userSized = false;
    bool inLayout = false;
    bool deferPaint = false; // theme switch: keep the old pixels until one final paint
    bool placedAbove = false;
    bool copied = false;
    bool trackingMouse = false;
    int dpi = 0; // monitor the popup is laid out for; 0 until the first placement
    int generation = 0;
    Vec<SelectionOnPage>* sourceSelection = nullptr;
    PopupHot hot = PopupHot::None;
    Rect closeRc{};
    Rect copyRc{};
    Rect headerRc{};
    Rect transRc{};
};

static InlineTranslatePopup* gPopup = nullptr;
static int gNextPopupGeneration = 1;

static void FreePopupData(InlineTranslatePopup* p) {
    str::FreePtr(&p->selection);
    str::FreePtr(&p->translation);
    str::FreePtr(&p->transError);
    str::FreePtr(&p->dstCode);
    if (p->fieldBrush) {
        DeleteObject(p->fieldBrush);
        p->fieldBrush = nullptr;
    }
    if (p->titleFont) {
        DeleteObject(p->titleFont);
        p->titleFont = nullptr;
    }
    if (p->bodyFont) {
        DeleteObject(p->bodyFont);
        p->bodyFont = nullptr;
    }
    if (p->hwndTip) {
        DestroyWindow(p->hwndTip);
        p->hwndTip = nullptr;
    }
}

static void CloseInlineTranslatePopupDismissingSelection() {
    CloseInlineTranslatePopup(true);
}

void CloseInlineTranslatePopup(bool clearSelection) {
    InlineTranslatePopup* p = gPopup;
    if (!p) {
        return;
    }
    MainWindow* win = p->win;
    Vec<SelectionOnPage>* sel = p->sourceSelection;
    gPopup = nullptr;
    p->closing = true;
    if (p->hwnd && IsWindow(p->hwnd)) {
        DestroyWindow(p->hwnd);
    }
    FreePopupData(p);
    delete p;
    // Keep the highlight while a lookup popup is still showing the same passage.
    if (clearSelection && !IsWordLookupVisible()) {
        ClearSelectionIfCurrent(win, sel);
    }
}

// Window procedures must not destroy their own window mid-message.
static void PostClosePopup() {
    uitask::Post(MkFunc0Void(CloseInlineTranslatePopupDismissingSelection), "CloseInlineTranslatePopup");
}

bool IsInlineTranslatePopupVisible() {
    return gPopup && gPopup->hwnd && IsWindowVisible(gPopup->hwnd);
}

static void SetEditTextUtf8(HWND hwnd, const char* s) {
    if (!hwnd) {
        return;
    }
    // multi-line edit controls only break lines on CRLF
    StrBuilder sb;
    for (const char* c = s ? s : ""; *c; c++) {
        if (*c == '\r') {
            continue;
        }
        if (*c == '\n') {
            sb.Append("\r\n");
        } else {
            sb.AppendChar(*c);
        }
    }
    SetWindowTextW(hwnd, ToWStrTemp(sb.size() > 0 ? sb.Get() : ""));
}

static const char* TransDisplayText(InlineTranslatePopup* p) {
    if (p->translating) {
        return _TRA("Translating…");
    }
    if (p->transError) {
        return p->transError;
    }
    return p->translation ? p->translation : "";
}

static int FontLineHeight(HWND hwnd, HFONT font) {
    HDC hdc = GetDC(hwnd);
    HFONT old = (HFONT)SelectObject(hdc, font);
    TEXTMETRICW tm{};
    GetTextMetricsW(hdc, &tm);
    SelectObject(hdc, old);
    ReleaseDC(hwnd, hdc);
    return tm.tmHeight + tm.tmExternalLeading;
}

static int MeasureTextHeight(HWND hwnd, HFONT font, const char* text, int width) {
    if (width < 1 || str::IsEmptyOrWhiteSpace(text)) {
        return 0;
    }
    HDC hdc = GetDC(hwnd);
    HFONT old = (HFONT)SelectObject(hdc, font);
    RECT rc{0, 0, width, 0};
    DrawTextW(hdc, ToWStrTemp(text), -1, &rc, DT_CALCRECT | DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX);
    SelectObject(hdc, old);
    ReleaseDC(hwnd, hdc);
    return rc.bottom - rc.top;
}

static int MeasureTextWidth(HWND hwnd, HFONT font, const char* text) {
    HDC hdc = GetDC(hwnd);
    HFONT old = (HFONT)SelectObject(hdc, font);
    RECT rc{};
    DrawTextW(hdc, ToWStrTemp(text ? text : ""), -1, &rc, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, old);
    ReleaseDC(hwnd, hdc);
    return rc.right - rc.left;
}

static Rect MonitorWorkArea(HWND hwnd) {
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mi);
    return ToRect(mi.rcWork);
}

static void SyncEditScrollbar(HWND edit, int contentH, int visibleH) {
    // Repeated hide/show calls recalculate the non-client area while text streams in.
    // ES_DISABLENOSCROLL was removed from the Windows SDK (it collided with ES_NUMBER).
    constexpr LONG kEditDisableNoScroll = 0x2000;
    if (GetWindowLongPtrW(edit, GWL_STYLE) & kEditDisableNoScroll) {
        return;
    }
    ShowScrollBar(edit, SB_VERT, contentH > visibleH);
}

// Prefer the DPI we chose for this monitor. GetDpiForWindow still reports the
// primary monitor until the popup is shown or WM_DPICHANGED arrives.
static int Px(HWND hwnd, int x) {
    auto* p = hwnd ? (InlineTranslatePopup*)GetWindowLongPtrW(hwnd, GWLP_USERDATA) : nullptr;
    int dpi = (p && p->dpi >= 72) ? p->dpi : DpiGet(hwnd);
    return MulDiv(x, dpi, 96);
}

// Language direction only. The engine name belongs on the larger popup.
static TempStr TranslateLangLabelTemp(InlineTranslatePopup* p) {
    const char* src = LangCodeUiName(p->srcCode);
    const char* dst = LangCodeUiName(p->dstCode);
    if (src && dst && !str::EqI(p->srcCode, p->dstCode)) {
        return str::FormatTemp("%s → %s", src, dst);
    }
    if (dst) {
        return str::DupTemp(dst);
    }
    return nullptr;
}

static void SyncCopyTip(InlineTranslatePopup* p) {
    if (!p || !p->hwndTip || !p->hwnd) {
        return;
    }
    TOOLINFOW ti{};
    ti.cbSize = sizeof(ti);
    ti.hwnd = p->hwnd;
    ti.uId = 1;
    SendMessageW(p->hwndTip, TTM_DELTOOLW, 0, (LPARAM)&ti);
    if (p->copyRc.IsEmpty()) {
        return;
    }
    ti.uFlags = TTF_SUBCLASS | TTF_TRANSPARENT;
    ti.rect = ToRECT(p->copyRc);
    static WCHAR tip[96];
    lstrcpynW(tip, ToWStrTemp(_TRA("Copy translation")), dimof(tip));
    ti.lpszText = tip;
    SendMessageW(p->hwndTip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
}

static void LayoutTranslateMinimal(InlineTranslatePopup* p) {
    HWND h = p->hwnd;

    int padX = Px(h, 12);
    int padY = Px(h, 4);
    int padBottom = Px(h, 18);
    int headerH = Px(h, 36);
    // Same box as the word-lookup close button.
    int closeSz = Px(h, 16);
    int copySz = Px(h, 16);
    int iconGap = Px(h, 6);
    HFONT reading = p->bodyFont ? p->bodyFont : p->font;
    const char* text = TransDisplayText(p);
    if (!text) {
        text = "";
    }
    Rect work = MonitorWorkArea(h);
    int minW = Px(h, 320);
    int maxW = std::min(Px(h, 380), std::max(1, work.dx - Px(h, 16)));
    if (maxW < minW) {
        minW = maxW;
    }
    bool showCopy = p->translation && !p->transError && !p->translating;
    TempStr lang = TranslateLangLabelTemp(p);
    int chromeW = padX + MeasureTextWidth(h, p->titleFont ? p->titleFont : p->font, _TRA("Translate"));
    if (!str::IsEmptyOrWhiteSpace(lang)) {
        chromeW += Px(h, 10) + MeasureTextWidth(h, p->font, lang);
    }
    chromeW += Px(h, 8) + closeSz + padX;
    if (showCopy) {
        chromeW += iconGap + copySz;
    }
    int textW = MeasureTextWidth(h, reading, text) + Px(h, 8);
    int wantW = std::max(chromeW, textW + padX * 2);
    wantW = limitValue(wantW, minW, maxW);
    int inner = std::max(1, wantW - padX * 2);
    int lineH = FontLineHeight(h, reading);
    int textH = MeasureTextHeight(h, reading, text, inner);
    if (textH > lineH) {
        textH += std::max(1, lineH / 5);
    }
    int maxH = std::max(headerH + padY + padBottom + lineH * 2, work.dy * 2 / 5);
    int wantH = headerH + padY + textH + padBottom;
    wantH = std::max(wantH, headerH + padY + lineH + padBottom);
    if (wantH > maxH) {
        wantH = maxH;
    }

    auto placeWindow = [&](int w, int ht) {
        Rect wr = WindowRect(h);
        int x = wr.x;
        int y = p->placedAbove ? wr.y + wr.dy - ht : wr.y;
        if (y + ht > work.y + work.dy) {
            y = work.y + work.dy - ht;
        }
        if (y < work.y) {
            y = work.y;
        }
        if (x + w > work.x + work.dx) {
            x = work.x + work.dx - w;
        }
        if (x < work.x) {
            x = work.x;
        }
        UINT flags = SWP_NOZORDER | SWP_NOACTIVATE;
        if (p->deferPaint) {
            flags |= SWP_NOREDRAW;
        }
        SetWindowPos(h, nullptr, x, y, w, ht, flags);
        UpdateFloatingPopupWindowRgn(h, kFloatingPopupCornerRadius, !p->deferPaint);
    };
    if (!p->userSized) {
        placeWindow(wantW, wantH);
    }

    auto placeFields = [&]() {
        Rect rc = ClientRect(h);
        p->headerRc = Rect(0, 0, rc.dx, headerH);
        int iconY = (headerH - closeSz) / 2;
        p->closeRc = Rect(rc.dx - padX - closeSz, iconY, closeSz, closeSz);
        if (showCopy) {
            p->copyRc = Rect(p->closeRc.x - iconGap - copySz, iconY, copySz, copySz);
        } else {
            p->copyRc = {};
        }
        int textTop = headerH + padY;
        int editRight = rc.dx - padX;
        int editW = std::max(1, editRight - padX);
        int fieldH = std::max(1, rc.dy - textTop - padBottom);
        p->transRc = Rect(padX, textTop, editW, fieldH);
        MoveWindow(p->hwndTrans, padX, textTop, editW, fieldH, TRUE);
        RECT fr{0, 0, std::max(1, editW - Px(h, 4)), std::max(1, fieldH)};
        SendMessageW(p->hwndTrans, EM_SETRECT, 0, (LPARAM)&fr);
    };
    placeFields();
    int editH = textH;
    int nChars = GetWindowTextLengthW(p->hwndTrans);
    if (nChars > 0) {
        LRESULT pos = SendMessageW(p->hwndTrans, EM_POSFROMCHAR, (WPARAM)(nChars - 1), 0);
        if (pos != (LRESULT)-1) {
            int charY = (short)HIWORD(pos);
            editH = std::max(editH, charY + lineH + Px(h, 4));
        }
    }
    if (!p->userSized && editH + headerH + padY + padBottom > wantH && wantH < maxH) {
        wantH = std::min(maxH, editH + headerH + padY + padBottom);
        Rect wr = WindowRect(h);
        placeWindow(wr.dx, wantH);
        placeFields();
    }
    int fieldH = std::max(1, p->transRc.dy);
    SyncEditScrollbar(p->hwndTrans, editH, fieldH);
    SyncCopyTip(p);
    ShowWindow(p->hwndTrans, SW_SHOWNA);
    InvalidateRect(h, nullptr, FALSE);
}

static void ApplyPopupFonts(InlineTranslatePopup* p, int dpi);

static void LayoutPopup(InlineTranslatePopup* p) {
    if (!p || !p->hwnd || p->inLayout) {
        return;
    }
    p->inLayout = true;
    defer {
        p->inLayout = false;
    };
    ApplyPopupFonts(p, DpiGet(p->hwnd));
    LayoutTranslateMinimal(p);
}

static bool PopupIconPressed(InlineTranslatePopup* p, PopupHot which) {
    return p && p->hot == which && (GetKeyState(VK_LBUTTON) & 0x8000) != 0;
}

static void DrawPopupIconHover(HDC hdc, const Rect& r, COLORREF col) {
    Gdiplus::Graphics g(hdc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPageUnit(Gdiplus::UnitPixel);
    Gdiplus::Color c;
    c.SetFromCOLORREF(col);
    Gdiplus::SolidBrush b(c);
    g.FillEllipse(&b, r.x, r.y, r.dx - 2, r.dy - 2);
}

static void AddRoundRect(Gdiplus::GraphicsPath& path, float x, float y, float w, float h, float radius) {
    float d = std::min(radius * 2.f, std::min(w, h));
    path.AddArc(x + w - d, y, d, d, 270, 90);
    path.AddArc(x + w - d, y + h - d, d, d, 0, 90);
    path.AddArc(x, y + h - d, d, d, 90, 90);
    path.AddArc(x, y, d, d, 180, 90);
    path.CloseFigure();
}

static void DrawCopyGlyph(HDC hdc, const Rect& r, COLORREF col, COLORREF cover) {
    Gdiplus::Graphics g(hdc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
    Gdiplus::Color c;
    c.SetFromCOLORREF(col);
    float side = (float)std::max(1, std::min(r.dx, r.dy));
    // Copy glyph: two equal rounded sheets. The rear one sits up-right.
    float penW = std::max(1.f, side * 1.25f / 16.f);
    float sheet = side * 0.50f;
    float shift = side * 0.20f;
    float margin = (side - sheet - shift) * 0.5f;
    float rad = sheet * 0.22f;
    Gdiplus::Pen pen(c, penW);
    pen.SetLineJoin(Gdiplus::LineJoinRound);
    float backX = (float)r.x + margin + shift;
    float backY = (float)r.y + margin;
    float frontX = (float)r.x + margin;
    float frontY = (float)r.y + margin + shift;
    Gdiplus::GraphicsPath back;
    AddRoundRect(back, backX, backY, sheet, sheet, rad);
    g.DrawPath(&pen, &back);
    Gdiplus::GraphicsPath front;
    AddRoundRect(front, frontX, frontY, sheet, sheet, rad);
    Gdiplus::Color coverCol;
    coverCol.SetFromCOLORREF(cover);
    Gdiplus::SolidBrush coverBr(coverCol);
    g.FillPath(&coverBr, &front);
    g.DrawPath(&pen, &front);
}

static void DrawCheckGlyph(HDC hdc, const Rect& r, COLORREF col) {
    Gdiplus::Graphics g(hdc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
    Gdiplus::Color c;
    c.SetFromCOLORREF(col);
    float side = (float)std::max(1, std::min(r.dx, r.dy));
    float penW = std::max(1.f, side * 1.35f / 16.f);
    Gdiplus::Pen pen(c, penW);
    pen.SetStartCap(Gdiplus::LineCapRound);
    pen.SetEndCap(Gdiplus::LineCapRound);
    pen.SetLineJoin(Gdiplus::LineJoinRound);
    Gdiplus::PointF pts[3] = {
        {r.x + side * 0.20f, r.y + side * 0.54f},
        {r.x + side * 0.40f, r.y + side * 0.74f},
        {r.x + side * 0.80f, r.y + side * 0.28f},
    };
    g.DrawLines(&pen, pts, 3);
}

static void PaintPopup(InlineTranslatePopup* p, HDC hdcWnd) {
    HWND h = p->hwnd;
    Rect rc = ClientRect(h);
    DoubleBuffer buffer(h, rc);
    HDC hdc = buffer.GetDC();

    COLORREF bg = FloatingPopupBg();
    COLORREF txt = FloatingPopupTextColor();
    COLORREF muted = FloatingPopupMutedTextColor();
    RECT full = ToRECT(rc);
    ScopedGdiObj<HBRUSH> bgBrush(CreateSolidBrush(bg));
    FillRect(hdc, &full, bgBrush);
    int radius = Px(h, kFloatingPopupCornerRadius);
    FillFloatingPopupRoundedRect(hdc, rc, radius, bg);
    StrokeFloatingPopupRoundedRect(hdc, rc, radius, FloatingPopupBorderColor());

    SetBkMode(hdc, TRANSPARENT);
    HFONT old = (HFONT)SelectObject(hdc, p->titleFont ? p->titleFont : p->font);

    SelectObject(hdc, p->titleFont ? p->titleFont : p->font);
    int rightLimit = rc.dx - Px(h, 8);
    if (!p->copyRc.IsEmpty()) {
        rightLimit = std::min(rightLimit, p->copyRc.x - Px(h, 6));
    }
    if (!p->closeRc.IsEmpty()) {
        rightLimit = std::min(rightLimit, p->closeRc.x - Px(h, 6));
    }
    RECT titleRc{Px(h, 12), p->headerRc.y, rightLimit, p->headerRc.y + p->headerRc.dy};
    SetTextColor(hdc, txt);
    const char* title = _TRA("Translate");
    DrawTextW(hdc, ToWStrTemp(title), -1, &titleRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    RECT measured = titleRc;
    DrawTextW(hdc, ToWStrTemp(title), -1, &measured, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, p->font);
    TempStr lang = TranslateLangLabelTemp(p);
    if (!str::IsEmptyOrWhiteSpace(lang)) {
        RECT langRc = titleRc;
        langRc.left = measured.right + Px(h, 10);
        if (langRc.left < langRc.right) {
            SetTextColor(hdc, muted);
            DrawTextW(hdc, ToWStrTemp(lang), -1, &langRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS |
                                                              DT_NOPREFIX);
        }
    }
    int ruleY = p->headerRc.y + p->headerRc.dy;
    {
        Gdiplus::Graphics rule(hdc);
        Gdiplus::Color ruleCol;
        ruleCol.SetFromCOLORREF(FloatingPopupSeparatorColor());
        Gdiplus::Pen rulePen(ruleCol, 1.f);
        float x0 = (float)Px(h, 12);
        float x1 = (float)std::max(Px(h, 12), rc.dx - Px(h, 12));
        rule.DrawLine(&rulePen, x0, (float)ruleY + 0.5f, x1, (float)ruleY + 0.5f);
    }
    if (!p->closeRc.IsEmpty()) {
        bool closeHot = p->hot == PopupHot::Close || PopupIconPressed(p, PopupHot::Close);
        DrawCloseButtonArgs cb;
        cb.hdc = hdc;
        cb.r = p->closeRc;
        cb.isHover = closeHot;
        cb.colX = muted;
        cb.colXHover = txt;
        cb.colHoverBg = FloatingPopupCloseHoverBg(bg);
        DrawCloseButton(cb);
    }
    if (!p->copyRc.IsEmpty()) {
        bool copyHot = p->hot == PopupHot::Copy || PopupIconPressed(p, PopupHot::Copy);
        COLORREF mark = (copyHot || p->copied) ? txt : muted;
        if (copyHot) {
            DrawPopupIconHover(hdc, p->copyRc, FloatingPopupCloseHoverBg(bg));
        }
        int glyph = Px(h, 14);
        int insetX = std::max(0, (p->copyRc.dx - glyph) / 2);
        int insetY = std::max(0, (p->copyRc.dy - glyph) / 2);
        Rect ink(p->copyRc.x + insetX, p->copyRc.y + insetY, glyph, glyph);
        if (p->copied) {
            DrawCheckGlyph(hdc, ink, mark);
        } else {
            DrawCopyGlyph(hdc, ink, mark, copyHot ? FloatingPopupCloseHoverBg(bg) : bg);
        }
    }
    SelectObject(hdc, old);
    buffer.Flush(hdcWnd);
}

static void ApplyEditTheme(HWND edit) {
    if (!edit) {
        return;
    }
    if (UseDarkModeLib() && ThemeUsesDarkChrome()) {
        DarkMode::setDarkScrollBar(edit);
    } else if (DynSetWindowTheme) {
        DynSetWindowTheme(edit, L"Explorer", nullptr);
    }
}

static void StripEditFrame(HWND hwnd);

static void ApplyPopupTheme(InlineTranslatePopup* p) {
    if (!p || !p->hwnd) {
        return;
    }
    if (p->fieldBrush) {
        DeleteObject(p->fieldBrush);
    }
    p->fieldBrush = CreateSolidBrush(FloatingPopupFieldBg());
    ApplyEditTheme(p->hwndTrans);
    if (p->hwndTrans) {
        StripEditFrame(p->hwndTrans);
        if (DynSetWindowTheme) {
            DynSetWindowTheme(p->hwndTrans, L"", L"");
        }
        if (UseDarkModeLib() && ThemeUsesDarkChrome()) {
            DarkMode::setDarkScrollBar(p->hwndTrans);
        }
    }
    UpdateFloatingPopupWindowRgn(p->hwnd, kFloatingPopupCornerRadius);
    if (!p->deferPaint) {
        RedrawWindow(p->hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
    }
}

// WM_SETREDRAW clears WS_VISIBLE. Put the bit back so the window stays logically
// visible and the old pixels stay on screen until the one final paint.
constexpr int kThemeFreezeMax = 4;
static HWND gThemeFrozen[kThemeFreezeMax];
static int gThemeFreezeCount = 0;

static void FreezeWindowRedraw(HWND hwnd) {
    if (!hwnd || gThemeFreezeCount >= kThemeFreezeMax) {
        return;
    }
    if ((GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_VISIBLE) == 0) {
        return;
    }
    SendMessageW(hwnd, WM_SETREDRAW, FALSE, 0);
    LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    if ((style & WS_VISIBLE) == 0) {
        SetWindowLongPtrW(hwnd, GWL_STYLE, style | WS_VISIBLE);
    }
    gThemeFrozen[gThemeFreezeCount++] = hwnd;
}

static void FreezePopupRedraw(InlineTranslatePopup* p) {
    gThemeFreezeCount = 0;
    p->deferPaint = true;
    FreezeWindowRedraw(p->hwndTrans);
    FreezeWindowRedraw(p->hwnd);
}

static void ThawPopupRedraw(InlineTranslatePopup* p) {
    HWND parent = p ? p->hwnd : nullptr;
    for (int i = 0; i < gThemeFreezeCount; i++) {
        HWND hwnd = gThemeFrozen[i];
        if (!hwnd || hwnd == parent) {
            continue;
        }
        bool keep = (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_VISIBLE) != 0;
        SendMessageW(hwnd, WM_SETREDRAW, TRUE, 0);
        if (!keep) {
            ShowWindow(hwnd, SW_HIDE);
        }
    }
    gThemeFreezeCount = 0;
    if (!p || !parent) {
        return;
    }
    bool keep = (GetWindowLongPtrW(parent, GWL_STYLE) & WS_VISIBLE) != 0;
    SendMessageW(parent, WM_SETREDRAW, TRUE, 0);
    p->deferPaint = false;
    if (!keep) {
        ShowWindow(parent, SW_HIDE);
        return;
    }
    RedrawWindow(parent, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME | RDW_UPDATENOW);
}

void RefreshInlineTranslatePopupTheme() {
    if (gPopup) {
        bool live = gPopup->hwnd && (GetWindowLongPtrW(gPopup->hwnd, GWL_STYLE) & WS_VISIBLE);
        if (live) {
            FreezePopupRedraw(gPopup);
        }
        ApplyPopupTheme(gPopup);
    }
}

void FinishInlineTranslatePopupTheme() {
    if (gThemeFreezeCount == 0) {
        if (gPopup) {
            gPopup->deferPaint = false;
        }
        return;
    }
    ThawPopupRedraw(gPopup);
}

static void ApplyPopupFonts(InlineTranslatePopup* p, int dpi);

static Rect SelectionAnchorScreen(MainWindow* win) {
    WindowTab* tab = win ? win->CurrentTab() : nullptr;
    DisplayModel* dm = tab ? tab->AsFixed() : nullptr;
    if (!dm || !tab->selectionOnPage || !win->hwndCanvas) {
        return Rect();
    }
    Rect u;
    bool any = false;
    for (SelectionOnPage& s : *tab->selectionOnPage) {
        Rect r = s.GetRect(dm);
        if (r.IsEmpty()) {
            continue;
        }
        POINT tl{r.x, r.y};
        POINT br{r.x + r.dx, r.y + r.dy};
        ClientToScreen(win->hwndCanvas, &tl);
        ClientToScreen(win->hwndCanvas, &br);
        Rect sr = Rect::FromXY((int)tl.x, (int)tl.y, (int)br.x, (int)br.y);
        if (!any) {
            u = sr;
            any = true;
        } else {
            u = Rect::FromXY(std::min(u.x, sr.x), std::min(u.y, sr.y), std::max(u.Right(), sr.Right()),
                             std::max(u.Bottom(), sr.Bottom()));
        }
    }
    return u;
}

static void PositionPopupNear(InlineTranslatePopup* p, Rect anchor, Point fallback) {
    HWND h = p->hwnd;
    bool has = !anchor.IsEmpty();
    int ax = has ? anchor.x + anchor.dx / 2 : fallback.x;
    int ay = has ? anchor.y + anchor.dy / 2 : fallback.y;
    HMONITOR mon = MonitorFromPoint({ax, ay}, MONITOR_DEFAULTTONEAREST);
    int dpi = DpiGetForMonitor(mon);
    if (dpi < 72) {
        dpi = DpiGet(h);
    }
    dpi = RoundUp(dpi, 4);
    ApplyPopupFonts(p, dpi);
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    GetMonitorInfoW(mon, &mi);
    Rect work = ToRect(mi.rcWork);
    int prefW = 380;
    int w = std::min(Px(h, prefW), std::max(1, work.dx - Px(h, 16)));
    int hgt = Px(h, 88);
    int gap = Px(h, 8);
    int expected = std::min(work.dy * 2 / 5, Px(h, 220));
    int x = 0;
    int y = 0;
    if (has) {
        int spaceAbove = anchor.y - work.y;
        p->placedAbove = spaceAbove >= std::min(expected, Px(h, 120)) + gap;
        x = anchor.x;
        y = p->placedAbove ? anchor.y - gap - hgt : anchor.y + anchor.dy + gap;
    } else {
        x = fallback.x - w / 2;
        y = fallback.y + gap;
        p->placedAbove = y + expected > work.y + work.dy && fallback.y - gap - expected >= work.y;
        if (p->placedAbove) {
            y = fallback.y - gap - hgt;
        }
    }
    x = limitValue(x, work.x, std::max(work.x, work.x + work.dx - w));
    y = limitValue(y, work.y, std::max(work.y, work.y + work.dy - hgt));
    SetWindowPos(h, nullptr, x, y, w, hgt, SWP_NOZORDER | SWP_NOACTIVATE);
    UpdateFloatingPopupWindowRgn(h, kFloatingPopupCornerRadius);
}

static LRESULT CALLBACK InlineTranslateWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

static void RegisterPopupClass() {
    static ATOM atom = 0;
    if (atom) {
        return;
    }
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = InlineTranslateWndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = kInlineTranslateClassName;
    atom = RegisterClassExW(&wc);
}

static HFONT CreateTitleFont(HFONT base) {
    LOGFONTW lf{};
    if (!base || !GetObjectW(base, sizeof(lf), &lf)) {
        return nullptr;
    }
    lf.lfWeight = FW_SEMIBOLD;
    return CreateFontIndirectW(&lf);
}

// A modest reading step above UI text. A fixed step, not a percentage,
// so a large UI font is not scaled again.
static HFONT CreateReadingFont(HFONT base, int dpi, int extraPoints = 2) {
    LOGFONTW lf{};
    if (!base || !GetObjectW(base, sizeof(lf), &lf)) {
        return nullptr;
    }
    if (dpi < 72) {
        dpi = 96;
    }
    int bump = std::max(MulDiv(extraPoints, dpi, 72), 1);
    if (lf.lfHeight < 0) {
        lf.lfHeight -= bump;
    } else if (lf.lfHeight > 0) {
        lf.lfHeight += bump;
    } else {
        lf.lfHeight = -MulDiv(11, dpi, 72);
    }
    return CreateFontIndirectW(&lf);
}

static void ApplyPopupFonts(InlineTranslatePopup* p, int dpi) {
    unsigned generation = GetUiFontGeneration();
    if (!p || !p->hwnd || dpi < 72 || (p->dpi == dpi && p->font && p->bodyFont && p->fontGeneration == generation)) {
        return;
    }
    p->dpi = dpi;
    // InvalidateUiFonts deletes borrowed HFONTs even when our DPI is unchanged.
    p->fontGeneration = generation;
    if (p->titleFont) {
        DeleteObject(p->titleFont);
        p->titleFont = nullptr;
    }
    if (p->bodyFont) {
        DeleteObject(p->bodyFont);
        p->bodyFont = nullptr;
    }
    p->font = GetAppFontForDpi(dpi);
    p->titleFont = CreateTitleFont(p->font);
    p->bodyFont = CreateReadingFont(p->font, dpi, 2);
    HFONT reading = p->bodyFont ? p->bodyFont : p->font;
    if (p->hwndTrans) {
        SendMessageW(p->hwndTrans, WM_SETFONT, (WPARAM)reading, TRUE);
    }
}

static void StripEditFrame(HWND hwnd) {
    if (!hwnd) {
        return;
    }
    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
    style &= ~(WS_BORDER | WS_DLGFRAME);
    ex &= ~(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE | WS_EX_WINDOWEDGE);
    SetWindowLongW(hwnd, GWL_STYLE, style);
    SetWindowLongW(hwnd, GWL_EXSTYLE, ex);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

static LRESULT CALLBACK TransSubclassProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) {
    if (msg == WM_SETCURSOR) {
        SetCursor(LoadCursor(nullptr, IDC_ARROW));
        return TRUE;
    }
    if (msg == WM_SETFOCUS || msg == WM_PAINT) {
        LRESULT r = DefSubclassProc(hwnd, msg, wp, lp);
        HideCaret(hwnd);
        return r;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

static InlineTranslatePopup* CreatePopup(MainWindow* win) {
    RegisterPopupClass();
    auto* p = new InlineTranslatePopup();
    p->win = win;
    int dpi = DpiGet(win->hwndFrame);
    p->dpi = dpi;
    p->font = GetAppFontForDpi(dpi);
    p->titleFont = CreateTitleFont(p->font);
    p->bodyFont = CreateReadingFont(p->font, dpi, 2);
    // Owned by the frame: stays above it and hides with it.
    DWORD ex = WS_EX_TOOLWINDOW;
    DWORD style = WS_POPUP | WS_CLIPCHILDREN;
    HWND parent = win->hwndFrame;
    p->hwnd = CreateWindowExW(ex, kInlineTranslateClassName, L"", style, 0, 0, 0, 0, parent, nullptr,
                              GetModuleHandle(nullptr), p);
    if (!p->hwnd) {
        FreePopupData(p);
        delete p;
        return nullptr;
    }
    HINSTANCE inst = GetModuleHandle(nullptr);
    DWORD roStyle = WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | ES_NOHIDESEL;
    p->hwndTrans = CreateWindowExW(0, WC_EDITW, L"", roStyle, 0, 0, 0, 0, p->hwnd, nullptr, inst, nullptr);
    if (p->hwndTrans) {
        SetWindowSubclass(p->hwndTrans, TransSubclassProc, kTransSubclassId, (DWORD_PTR)p);
        p->hwndTip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
                                     CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, p->hwnd, nullptr, inst,
                                     nullptr);
        if (p->hwndTip) {
            int maxTip = Px(p->hwnd, 220);
            SendMessageW(p->hwndTip, TTM_SETMAXTIPWIDTH, 0, maxTip);
        }
    }
    HFONT reading = p->bodyFont ? p->bodyFont : p->font;
    SendMessageW(p->hwndTrans, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, 0);
    SendMessageW(p->hwndTrans, WM_SETFONT, (WPARAM)reading, FALSE);
    ApplyPopupTheme(p);
    return p;
}

// Reuses the open popup for the same window; a new session always starts clean.
static InlineTranslatePopup* BeginPopupSession(MainWindow* win, const char* selection) {
    if (gPopup && gPopup->win != win) {
        CloseInlineTranslatePopup();
    }
    if (!gPopup) {
        gPopup = CreatePopup(win);
        if (!gPopup) {
            return nullptr;
        }
    }
    InlineTranslatePopup* p = gPopup;
    WindowTab* tab = win->CurrentTab();
    p->sourceSelection = tab ? tab->selectionOnPage : nullptr;
    // global so a late result from a closed popup can't match a new one
    p->generation = ++gNextPopupGeneration;
    p->translating = false;
    p->userSized = false;
    p->copied = false;
    p->srcCode = nullptr;
    KillTimer(p->hwnd, kCopiedTimerId);
    str::ReplacePtr(&p->selection, NormalizeSelectionText(selection));
    str::FreePtr(&p->translation);
    str::FreePtr(&p->transError);
    str::FreePtr(&p->dstCode);
    SetEditTextUtf8(p->hwndTrans, "");

    POINT cur{};
    GetCursorPos(&cur);
    PositionPopupNear(p, SelectionAnchorScreen(win), Point{cur.x, cur.y});
    return p;
}

static void ShowPopup(InlineTranslatePopup* p) {
    LayoutPopup(p);
    // don't steal focus from the document; clicking into the popup activates it
    ShowWindow(p->hwnd, SW_SHOWNA);
}

static void RefreshTranslationView(InlineTranslatePopup* p) {
    SetEditTextUtf8(p->hwndTrans, TransDisplayText(p));
    LayoutPopup(p);
}

static char* TruncateForTranslate(const char* s) {
    if (!s) {
        return str::Dup("");
    }
    const u8* p = (const u8*)s;
    int runes = 0;
    while (*p && runes < kMaxTranslateChars) {
        int n = utf8RuneLen(p);
        if (n < 1) {
            break;
        }
        p += n;
        runes++;
    }
    return str::Dup(s, (size_t)(p - (const u8*)s));
}

struct TranslateJob {
    int generation = 0;
    char* text = nullptr;
    char* target = nullptr;
    char* ak = nullptr;
    char* sk = nullptr;
    char* result = nullptr;
    char* error = nullptr;
};

static void TranslateJobFinished(TranslateJob* job) {
    defer {
        str::Free(job->text);
        str::Free(job->target);
        str::Free(job->ak);
        str::Free(job->sk);
        str::Free(job->result);
        str::Free(job->error);
        delete job;
    };
    InlineTranslatePopup* p = gPopup;
    if (!p || p->generation != job->generation) {
        return;
    }
    p->translating = false;
    if (job->result) {
        str::ReplacePtr(&p->translation, job->result);
        job->result = nullptr;
    } else {
        TempStr err = str::FormatTemp("%s\n%s", _TRA("Translation failed."), job->error ? job->error : "");
        str::ReplaceWithCopy(&p->transError, err);
    }
    RefreshTranslationView(p);
    // Stay hidden until there is something to show.
    if (!IsWindowVisible(p->hwnd)) {
        ShowPopup(p);
    }
}

static void TranslateJobWorker(TranslateJob* job) {
    if (char* cached = CacheLookup(job->text, job->target)) {
        job->result = cached;
    } else {
        char* volcErr = nullptr;
        if (!VolcTranslateText(job->ak, job->sk, job->text, job->target, &job->result, &volcErr)) {
            job->error = volcErr;
            volcErr = nullptr;
        }
        str::Free(volcErr);
        if (job->result) {
            CacheStore(job->text, job->target, job->result);
        }
    }
    uitask::Post(MkFunc0(TranslateJobFinished, job), "InlineTranslateDone");
}

static void StartTranslate(InlineTranslatePopup* p) {
    p->translating = true;
    auto* job = new TranslateJob();
    job->generation = p->generation;
    job->text = TruncateForTranslate(p->selection);
    job->target = str::Dup(p->dstCode);
    job->ak = str::Dup(gGlobalPrefs->translateVolcAccessKey);
    job->sk = str::Dup(gGlobalPrefs->translateVolcSecretKey);
    RunAsync(MkFunc0(TranslateJobWorker, job), "InlineTranslate");
    RefreshTranslationView(p);
}

static void CopyTranslation(InlineTranslatePopup* p) {
    if (!p->translation || !CopyTextToClipboard(p->translation)) {
        return;
    }
    p->copied = true;
    SetTimer(p->hwnd, kCopiedTimerId, kCopiedFlashMs, nullptr);
    InvalidateRect(p->hwnd, nullptr, FALSE);
}

static PopupHot HitTestHot(InlineTranslatePopup* p, Point pt) {
    if (p->closeRc.Contains(pt)) {
        return PopupHot::Close;
    }
    if (!p->copyRc.IsEmpty() && p->copyRc.Contains(pt)) {
        return PopupHot::Copy;
    }
    return PopupHot::None;
}

static LRESULT PopupNcHitTest(InlineTranslatePopup* p, LPARAM lp) {
    POINT pt{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
    ScreenToClient(p->hwnd, &pt);
    Point cpt{pt.x, pt.y};
    if (HitTestHot(p, cpt) != PopupHot::None) {
        return HTCLIENT;
    }
    // Header blank space drags. The translation body does not.
    bool inHeader = pt.y >= p->headerRc.y && pt.y < p->headerRc.y + p->headerRc.dy;
    if (inHeader) {
        return HTCAPTION;
    }
    return HTCLIENT;
}

static LRESULT CALLBACK InlineTranslateWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = (CREATESTRUCTW*)lp;
        auto* created = (InlineTranslatePopup*)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)created);
        if (created) {
            created->hwnd = hwnd;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    auto* p = (InlineTranslatePopup*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (!p) {
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            if (!p->deferPaint) {
                PaintPopup(p, hdc);
            }
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORSTATIC: {
            HDC hdc = (HDC)wp;
            HWND ctl = (HWND)lp;
            bool dim = ctl == p->hwndTrans && (p->translating || p->transError);
            COLORREF bg = ctl == p->hwndTrans ? FloatingPopupBg() : FloatingPopupFieldBg();
            SetTextColor(hdc, dim ? FloatingPopupMutedTextColor() : FloatingPopupTextColor());
            SetBkColor(hdc, bg);
            HBRUSH& brush = p->fieldBrush;
            if (brush) {
                DeleteObject(brush);
            }
            brush = CreateSolidBrush(bg);
            return (LRESULT)brush;
        }
        case WM_NCHITTEST:
            return PopupNcHitTest(p, lp);
        case WM_NCLBUTTONDBLCLK:
            // no maximize on header double-click
            return 0;
        case WM_SETCURSOR:
            break;
        case WM_SIZING:
            p->userSized = true;
            break;
        case WM_GETMINMAXINFO: {
            auto* mmi = (MINMAXINFO*)lp;
            mmi->ptMinTrackSize.x = Px(hwnd, 320);
            mmi->ptMinTrackSize.y = Px(hwnd, 72);
            return 0;
        }
        case WM_DPICHANGED: {
            int dpi = (int)LOWORD(wp);
            if (dpi < 72) {
                dpi = 96;
            }
            dpi = RoundUp(dpi, 4);
            ApplyPopupFonts(p, dpi);
            auto* prc = (RECT*)lp;
            SetWindowPos(hwnd, nullptr, prc->left, prc->top, prc->right - prc->left, prc->bottom - prc->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            if (IsWindowVisible(hwnd)) {
                LayoutPopup(p);
            }
            return 0;
        }
        case WM_SIZE:
            UpdateFloatingPopupWindowRgn(hwnd, kFloatingPopupCornerRadius, !p->deferPaint);
            LayoutPopup(p);
            return 0;
        case WM_MOUSEMOVE: {
            PopupHot hot = HitTestHot(p, Point{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)});
            if (hot != p->hot) {
                p->hot = hot;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            if (!p->trackingMouse) {
                TRACKMOUSEEVENT tme{sizeof(tme), TME_LEAVE, hwnd, 0};
                p->trackingMouse = TrackMouseEvent(&tme);
            }
            return 0;
        }
        case WM_MOUSELEAVE:
            p->trackingMouse = false;
            if (p->hot != PopupHot::None) {
                p->hot = PopupHot::None;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        case WM_LBUTTONDOWN: {
            PopupHot hot = HitTestHot(p, Point{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)});
            if (hot == PopupHot::Close || hot == PopupHot::Copy) {
                SetCapture(hwnd);
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            break;
        }
        case WM_LBUTTONUP: {
            if (GetCapture() == hwnd) {
                ReleaseCapture();
            }
            PopupHot hot = HitTestHot(p, Point{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)});
            if (hot == PopupHot::Close) {
                PostClosePopup();
            } else if (hot == PopupHot::Copy) {
                CopyTranslation(p);
            }
            return 0;
        }
        case WM_TIMER:
            if (wp == kCopiedTimerId) {
                KillTimer(hwnd, kCopiedTimerId);
                p->copied = false;
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            break;
        case WM_ACTIVATE:
            // Clicking another app deactivates a focused translation popup.
            if (LOWORD(wp) == WA_INACTIVE && !p->closing) {
                PostClosePopup();
                return 0;
            }
            break;
        case WM_CLOSE:
            PostClosePopup();
            return 0;
        case WM_NCDESTROY:
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            p->hwnd = nullptr;
            if (!p->closing) {
                // destroyed together with the owner frame
                if (gPopup == p) {
                    gPopup = nullptr;
                }
                FreePopupData(p);
                delete p;
            }
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// A click or scroll outside the translation popup dismisses it, as word lookup does.
static bool TranslateDismissOutside(InlineTranslatePopup* p, const MSG& msg) {
    bool clearSelection = false;
    switch (msg.message) {
        case WM_LBUTTONDOWN:
        case WM_MBUTTONDOWN:
        case WM_NCLBUTTONDOWN:
        case WM_NCMBUTTONDOWN:
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
            clearSelection = true;
            break;
        case WM_RBUTTONDOWN:
        case WM_NCRBUTTONDOWN:
            break;
        default:
            return false;
    }
    if (msg.hwnd == p->hwnd || IsChild(p->hwnd, msg.hwnd)) {
        return false;
    }
    CloseInlineTranslatePopup(clearSelection);
    return true;
}

bool InlineTranslatePopupPreTranslate(MSG& msg) {
    InlineTranslatePopup* p = gPopup;
    if (!p || !p->hwnd || !IsWindowVisible(p->hwnd)) {
        return false;
    }
    if (TranslateDismissOutside(p, msg)) {
        return false;
    }
    if (msg.message < WM_KEYFIRST || msg.message > WM_KEYLAST) {
        return false;
    }
    bool inPopup = msg.hwnd == p->hwnd || IsChild(p->hwnd, msg.hwnd);
    if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
        bool fromOwner = !inPopup && p->win && FindMainWindowByHwnd(msg.hwnd) == p->win;
        if (!inPopup && !fromOwner) {
            return false;
        }
        MainWindow* win = p->win;
        CloseInlineTranslatePopup();
        if (inPopup && win && IsMainWindowValid(win)) {
            HwndSetFocus(win->hwndCanvas);
        }
        return true;
    }
    if (!inPopup) {
        return false;
    }
    // keep the app's single-key accelerators (and Ctrl+C on the document
    // selection) away from text typed or copied in the popup
    TranslateMessage(&msg);
    DispatchMessage(&msg);
    return true;
}

static TempStr GetSelectionOrNotify(WindowTab* tab) {
    if (!tab || !tab->win || !HasPermission(Perm::CopySelection)) {
        return nullptr;
    }
    bool isTextOnly = false;
    TempStr sel = GetSelectedTextTemp(tab, "\n", isTextOnly);
    if (str::IsEmptyOrWhiteSpace(sel)) {
        return nullptr;
    }
    DisplayModel* dm = tab->AsFixed();
    if (dm && !gDisableDocumentRestrictions && !dm->GetEngine()->AllowsCopyingText()) {
        NotificationCreateArgs args;
        args.hwndParent = tab->win->hwndCanvas;
        args.msg = _TRA("Copying text was denied");
        args.timeoutMs = 3000;
        ShowNotification(args);
        return nullptr;
    }
    return sel;
}

void TranslateSelectionInTab(MainWindow* win, WindowTab* tab) {
    if (!win || !tab || !gGlobalPrefs || !gGlobalPrefs->enableInlineTranslate) {
        return;
    }
    if (!HasPermission(Perm::InternetAccess)) {
        return;
    }
    TempStr sel = GetSelectionOrNotify(tab);
    if (!sel) {
        return;
    }
    HideSelectionToolbar(win);
    InlineTranslatePopup* p = BeginPopupSession(win, sel);
    if (!p) {
        return;
    }
    p->srcCode = RoughLangCode(DetectSourceLangRough(p->selection));
    p->dstCode =
        str::Dup(ResolveTranslateTarget(p->selection, gGlobalPrefs->translateTargetMode, trans::GetCurrentLangCode()));
    if (!InlineTranslateVolcIsConfigured()) {
        str::ReplaceWithCopy(&p->transError,
                             _TRA("No translation service is set up yet. Add Volcengine Translate keys in Settings → "
                                  "Translate."));
        RefreshTranslationView(p);
        ShowPopup(p);
        return;
    }
    StartTranslate(p);
}

