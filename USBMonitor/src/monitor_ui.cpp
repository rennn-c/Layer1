// monitor_ui.cpp
// ─────────────────────────────────────────────────────────────────────────────
// USB Descriptor Monitor — Standalone Desktop UI
// Features:
//   - Live event list with draggable splitter to resize detail box
//   - Filter bar: verdict, device class, date range
//   - Toggle: show all history vs currently connected devices only
//   - Allow/Block list management
// ─────────────────────────────────────────────────────────────────────────────

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <set>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' \
    name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
    processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ─── Constants ───────────────────────────────────────────────────────────────

#define CSV_PATH L"C:\\ProgramData\\USBMonitor\\usb_descriptors.csv"
#define ALLOW_PATH L"C:\\ProgramData\\USBMonitor\\allowlist.txt"
#define BLOCK_PATH L"C:\\ProgramData\\USBMonitor\\blocklist.txt"

#define REFRESH_TIMER_ID 1
#define REFRESH_INTERVAL 2000

#define ID_TAB 100
#define ID_LIST_EVENTS 101
#define ID_LIST_ALLOW 102
#define ID_LIST_BLOCK 103
#define ID_BTN_ADD_ALLOW 104
#define ID_BTN_REMOVE_ALLOW 105
#define ID_BTN_ADD_BLOCK 106
#define ID_BTN_REMOVE_BLOCK 107
#define ID_BTN_REFRESH 108
#define ID_DETAIL_BOX 109
#define ID_STAT_CLEAN 110
#define ID_STAT_SUSPICIOUS 111
#define ID_STAT_ALERT 112
#define ID_STAT_BLOCKED 113
#define ID_FILTER_VERDICT 114
#define ID_FILTER_CLASS 115
#define ID_FILTER_DATE_FROM 116
#define ID_FILTER_DATE_TO 117
#define ID_TOGGLE_CURRENT 118
#define ID_BTN_CLEAR_FILTER 119
#define ID_LABEL_FROM 120
#define ID_LABEL_TO 121

#define SPLITTER_H 6 // Height of the draggable splitter bar in pixels

// ─── Data Structures ─────────────────────────────────────────────────────────

struct USBEvent
{
    std::wstring timestamp, instanceId, vendorId, productId;
    std::wstring description, manufacturer, product, serialNumber;
    std::wstring deviceClass, service, location;
    std::wstring hasHID, hasMassStorage, hasCDC, hasVendorClass, isComposite;
    std::wstring verdict, reasons;
};

struct ListEntry
{
    std::wstring vidPid, note;
};

// ─── Globals ─────────────────────────────────────────────────────────────────

HWND g_hWnd = nullptr, g_hTab = nullptr;
HWND g_hListEvents = nullptr, g_hListAllow = nullptr, g_hListBlock = nullptr;
HWND g_hDetail = nullptr;
HWND g_hStatClean = nullptr, g_hStatSusp = nullptr;
HWND g_hStatAlert = nullptr, g_hStatBlock = nullptr;
HWND g_hFilterVerdict = nullptr, g_hFilterClass = nullptr;
HWND g_hFilterDateFrom = nullptr, g_hFilterDateTo = nullptr;
HWND g_hToggleCurrent = nullptr;

std::vector<USBEvent> g_events;
std::vector<USBEvent> g_filtered;
std::vector<ListEntry> g_allowList, g_blockList;
int g_activeTab = 0;

// ─── Splitter State ───────────────────────────────────────────────────────────

int g_splitterY = 400; // Y position of splitter bar
bool g_dragging = false;
int g_dragOffsetY = 0;

// ─── File Time Tracking ───────────────────────────────────────────────────────

FILETIME g_lastCSVTime{}, g_lastAllowTime{}, g_lastBlockTime{};

FILETIME getFileTime(const std::wstring &path)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    FILETIME ft{};
    if (h != INVALID_HANDLE_VALUE)
    {
        GetFileTime(h, nullptr, nullptr, &ft);
        CloseHandle(h);
    }
    return ft;
}

// ─── String Utilities ─────────────────────────────────────────────────────────

std::wstring strToWstr(const std::string &s)
{
    if (s.empty())
        return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

std::wstring trimField(const std::wstring &s)
{
    std::wstring r = s;
    if (r.size() >= 2 && r.front() == L'"' && r.back() == L'"')
        r = r.substr(1, r.size() - 2);
    std::wstring out;
    for (size_t i = 0; i < r.size(); i++)
    {
        if (r[i] == L'"' && i + 1 < r.size() && r[i + 1] == L'"')
        {
            out += L'"';
            i++;
        }
        else
            out += r[i];
    }
    return out;
}

std::vector<std::wstring> splitCSV(const std::wstring &line)
{
    std::vector<std::wstring> fields;
    std::wstring field;
    bool inQ = false;
    for (size_t i = 0; i < line.size(); i++)
    {
        wchar_t c = line[i];
        if (c == L'"')
        {
            if (inQ && i + 1 < line.size() && line[i + 1] == L'"')
            {
                field += L'"';
                i++;
            }
            else
                inQ = !inQ;
        }
        else if (c == L',' && !inQ)
        {
            fields.push_back(field);
            field.clear();
        }
        else
            field += c;
    }
    fields.push_back(field);
    return fields;
}

std::wstring todayStr()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[16];
    swprintf_s(buf, L"%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
    return buf;
}

// ─── Currently Connected Devices ─────────────────────────────────────────────
// Queries SetupAPI for all USB devices currently present in the system.
// Returns a set of instance ID strings used to filter the event history.

std::set<std::wstring> getCurrentlyConnectedIDs()
{
    std::set<std::wstring> ids;
    HDEVINFO devInfo = SetupDiGetClassDevsW(nullptr, L"USB", nullptr,
                                            DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (devInfo == INVALID_HANDLE_VALUE)
        return ids;
    SP_DEVINFO_DATA devData{};
    devData.cbSize = sizeof(devData);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(devInfo, i, &devData); i++)
    {
        WCHAR idW[MAX_DEVICE_ID_LEN]{};
        CM_Get_Device_IDW(devData.DevInst, idW, MAX_DEVICE_ID_LEN, 0);
        std::wstring id = idW;
        if (id.find(L"USB\\VID_") != std::wstring::npos)
            ids.insert(id);
    }
    SetupDiDestroyDeviceInfoList(devInfo);
    return ids;
}

// ─── File I/O ─────────────────────────────────────────────────────────────────

void loadCSV()
{
    g_events.clear();
    std::wifstream f(CSV_PATH);
    if (!f)
        return;
    std::wstring line;
    std::getline(f, line);
    while (std::getline(f, line))
    {
        if (line.empty())
            continue;
        auto flds = splitCSV(line);
        if (flds.size() < 21)
            continue;
        USBEvent e;
        e.timestamp = trimField(flds[0]);
        e.instanceId = trimField(flds[1]);
        e.vendorId = trimField(flds[2]);
        e.productId = trimField(flds[3]);
        e.description = trimField(flds[4]);
        e.manufacturer = trimField(flds[5]);
        e.product = trimField(flds[6]);
        e.serialNumber = trimField(flds[7]);
        e.deviceClass = trimField(flds[8]);
        e.service = trimField(flds[9]);
        e.location = trimField(flds[10]);
        e.hasHID = trimField(flds[11]);
        e.hasMassStorage = trimField(flds[12]);
        e.hasCDC = trimField(flds[13]);
        e.hasVendorClass = trimField(flds[14]);
        e.isComposite = trimField(flds[15]);
        e.verdict = trimField(flds[19]);
        e.reasons = trimField(flds[20]);
        g_events.push_back(e);
    }
}

void loadListFile(const std::wstring &path, std::vector<ListEntry> &out)
{
    out.clear();
    std::wifstream f(path);
    if (!f)
        return;
    std::wstring line;
    while (std::getline(f, line))
    {
        std::wstring note;
        auto h = line.find(L'#');
        if (h != std::wstring::npos)
        {
            note = line.substr(h + 1);
            line = line.substr(0, h);
        }
        auto s = line.find_first_not_of(L" \t\r\n");
        if (s == std::wstring::npos)
            continue;
        line = line.substr(s);
        auto e2 = line.find_last_not_of(L" \t\r\n");
        if (e2 != std::wstring::npos)
            line = line.substr(0, e2 + 1);
        if (line.empty())
            continue;
        auto ns = note.find_first_not_of(L" \t");
        if (ns != std::wstring::npos)
            note = note.substr(ns);
        ListEntry entry;
        entry.vidPid = line;
        entry.note = note;
        out.push_back(entry);
    }
}

void saveListFile(const std::wstring &path,
                  const std::vector<ListEntry> &entries,
                  const std::string &listName)
{
    std::wofstream f(path);
    f << L"# USB Monitor - " << strToWstr(listName) << L"\n";
    f << L"# Format: VID:PID  # optional note\n\n";
    for (const auto &e : entries)
    {
        f << e.vidPid;
        if (!e.note.empty())
            f << L"  # " << e.note;
        f << L"\n";
    }
}

// ─── Filtering ────────────────────────────────────────────────────────────────

// Reads current filter control states and rebuilds g_filtered from g_events.
// Supports: verdict, device class, date range, and current-only toggle.
void applyFilters()
{
    int verdictIdx = (int)SendMessageW(g_hFilterVerdict, CB_GETCURSEL, 0, 0);
    const wchar_t *verdicts[] = {L"", L"CLEAN", L"SUSPICIOUS", L"ALERT", L"BLOCKED"};
    std::wstring filterVerdict = (verdictIdx > 0) ? verdicts[verdictIdx] : L"";

    int classIdx = (int)SendMessageW(g_hFilterClass, CB_GETCURSEL, 0, 0);

    wchar_t fromBuf[32]{}, toBuf[32]{};
    GetWindowTextW(g_hFilterDateFrom, fromBuf, 32);
    GetWindowTextW(g_hFilterDateTo, toBuf, 32);
    std::wstring dateFrom = fromBuf, dateTo = toBuf;

    bool currentOnly = (SendMessageW(g_hToggleCurrent, BM_GETCHECK, 0, 0) == BST_CHECKED);
    std::set<std::wstring> connectedIDs;
    if (currentOnly)
        connectedIDs = getCurrentlyConnectedIDs();

    g_filtered.clear();
    std::set<std::wstring> seenIds;

    // Iterate in reverse (newest first) to deduplicate when showing current only
    for (int i = (int)g_events.size() - 1; i >= 0; i--)
    {
        const auto &e = g_events[i];

        // Current-only: skip if not in connected set, skip duplicates
        if (currentOnly)
        {
            if (!connectedIDs.count(e.instanceId))
                continue;
            if (seenIds.count(e.instanceId))
                continue;
            seenIds.insert(e.instanceId);
        }

        // Verdict filter
        if (!filterVerdict.empty() && e.verdict != filterVerdict)
            continue;

        // Class filter
        if (classIdx == 1 && e.hasHID != L"1")
            continue;
        if (classIdx == 2 && e.hasMassStorage != L"1")
            continue;
        if (classIdx == 3 && e.hasCDC != L"1")
            continue;
        if (classIdx == 4 && e.isComposite != L"1")
            continue;

        // Date range filter (compares "YYYY-MM-DD" prefix of timestamp)
        if (!dateFrom.empty() && e.timestamp.size() >= 10 &&
            e.timestamp.substr(0, 10) < dateFrom)
            continue;
        if (!dateTo.empty() && e.timestamp.size() >= 10 &&
            e.timestamp.substr(0, 10) > dateTo)
            continue;

        g_filtered.push_back(e);
    }

    // Restore chronological order unless showing current-only
    if (!currentOnly)
        std::reverse(g_filtered.begin(), g_filtered.end());
}

// ─── Stats ────────────────────────────────────────────────────────────────────

void updateStats()
{
    int clean = 0, susp = 0, alert = 0, blocked = 0;
    for (const auto &e : g_events)
    {
        if (e.verdict == L"CLEAN")
            clean++;
        else if (e.verdict == L"SUSPICIOUS")
            susp++;
        else if (e.verdict == L"ALERT")
            alert++;
        else if (e.verdict == L"BLOCKED")
            blocked++;
    }
    SetWindowTextW(g_hStatClean, (L"Clean: " + std::to_wstring(clean)).c_str());
    SetWindowTextW(g_hStatSusp, (L"Suspicious: " + std::to_wstring(susp)).c_str());
    SetWindowTextW(g_hStatAlert, (L"Alert: " + std::to_wstring(alert)).c_str());
    SetWindowTextW(g_hStatBlock, (L"Blocked: " + std::to_wstring(blocked)).c_str());
}

// ─── ListView Helpers ─────────────────────────────────────────────────────────

void addColumn(HWND hList, int col, const wchar_t *title, int width)
{
    LVCOLUMNW lvc{};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.cx = width;
    lvc.pszText = (LPWSTR)title;
    lvc.iSubItem = col;
    ListView_InsertColumn(hList, col, &lvc);
}

void insertRow(HWND hList, int row, const std::vector<std::wstring> &cols)
{
    LVITEMW lvi{};
    lvi.mask = LVIF_TEXT;
    lvi.iItem = row;
    lvi.iSubItem = 0;
    lvi.pszText = (LPWSTR)cols[0].c_str();
    ListView_InsertItem(hList, &lvi);
    for (int i = 1; i < (int)cols.size(); i++)
        ListView_SetItemText(hList, row, i, (LPWSTR)cols[i].c_str());
}

// ─── UI Population ────────────────────────────────────────────────────────────

void populateEvents()
{
    applyFilters();
    ListView_DeleteAllItems(g_hListEvents);
    for (int i = 0; i < (int)g_filtered.size(); i++)
    {
        const auto &e = g_filtered[i];
        insertRow(g_hListEvents, i, {e.timestamp, e.description, e.manufacturer, e.vendorId + L":" + e.productId, e.deviceClass, e.verdict, e.reasons});
    }
}

void populateAllowList()
{
    ListView_DeleteAllItems(g_hListAllow);
    for (int i = 0; i < (int)g_allowList.size(); i++)
        insertRow(g_hListAllow, i, {g_allowList[i].vidPid, g_allowList[i].note});
}

void populateBlockList()
{
    ListView_DeleteAllItems(g_hListBlock);
    for (int i = 0; i < (int)g_blockList.size(); i++)
        insertRow(g_hListBlock, i, {g_blockList[i].vidPid, g_blockList[i].note});
}

void showEventDetail(int index)
{
    if (index < 0 || index >= (int)g_filtered.size())
        return;
    const auto &e = g_filtered[index];
    std::wostringstream ss;
    ss << L"=== Device Descriptor ===\r\n"
       << L"Timestamp:    " << e.timestamp << L"\r\n"
       << L"Description:  " << e.description << L"\r\n"
       << L"Manufacturer: " << e.manufacturer << L"\r\n"
       << L"Product:      " << e.product << L"\r\n"
       << L"Serial:       " << e.serialNumber << L"\r\n"
       << L"Class:        " << e.deviceClass << L"\r\n"
       << L"Service:      " << e.service << L"\r\n"
       << L"Location:     " << e.location << L"\r\n"
       << L"VendorID:     " << e.vendorId << L"\r\n"
       << L"ProductID:    " << e.productId << L"\r\n"
       << L"\r\n=== Interfaces ===\r\n"
       << L"HID:          " << (e.hasHID == L"1" ? L"YES" : L"no") << L"\r\n"
       << L"MassStorage:  " << (e.hasMassStorage == L"1" ? L"YES" : L"no") << L"\r\n"
       << L"CDC/Serial:   " << (e.hasCDC == L"1" ? L"YES" : L"no") << L"\r\n"
       << L"VendorClass:  " << (e.hasVendorClass == L"1" ? L"YES" : L"no") << L"\r\n"
       << L"Composite:    " << (e.isComposite == L"1" ? L"YES" : L"no") << L"\r\n"
       << L"\r\n=== Layer 1 Verdict ===\r\n"
       << L"Verdict:  " << e.verdict << L"\r\n"
       << L"Reasons:  " << e.reasons << L"\r\n"
       << L"\r\nInstance ID:\r\n"
       << e.instanceId << L"\r\n";
    SetWindowTextW(g_hDetail, ss.str().c_str());
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

void doRefresh(bool force = false)
{
    FILETIME csvT = getFileTime(CSV_PATH), allowT = getFileTime(ALLOW_PATH), blockT = getFileTime(BLOCK_PATH);
    if (force || CompareFileTime(&csvT, &g_lastCSVTime) != 0)
    {
        loadCSV();
        populateEvents();
        updateStats();
        g_lastCSVTime = csvT;
    }
    if (force || CompareFileTime(&allowT, &g_lastAllowTime) != 0)
    {
        loadListFile(ALLOW_PATH, g_allowList);
        populateAllowList();
        g_lastAllowTime = allowT;
    }
    if (force || CompareFileTime(&blockT, &g_lastBlockTime) != 0)
    {
        loadListFile(BLOCK_PATH, g_blockList);
        populateBlockList();
        g_lastBlockTime = blockT;
    }
}

// ─── Layout ───────────────────────────────────────────────────────────────────

// Repositions all controls based on current window size and splitter position.
// Called on WM_SIZE and whenever the splitter is dragged.
void relayout(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    int statH = 28;   // Height of stat bar
    int filterH = 30; // Height of filter bar
    int tabTopY = statH + filterH;
    int tabHdrH = 28; // Height of tab strip header
    int innerTop = tabTopY + tabHdrH + 2;

    // Clamp splitter within usable area
    int minList = 60, minDetail = 40;
    if (g_splitterY < innerTop + minList)
        g_splitterY = innerTop + minList;
    if (g_splitterY > H - minDetail - SPLITTER_H)
        g_splitterY = H - minDetail - SPLITTER_H;

    int listH = g_splitterY - innerTop;
    int detailY = g_splitterY + SPLITTER_H;
    int detailH = H - detailY;
    int btnY = H - 40;

    if (g_hTab)
        SetWindowPos(g_hTab, nullptr, 0, tabTopY, W, H - tabTopY, SWP_NOZORDER);

    if (g_hListEvents)
        SetWindowPos(g_hListEvents, nullptr, 5, innerTop, W - 10, listH, SWP_NOZORDER);
    if (g_hDetail)
        SetWindowPos(g_hDetail, nullptr, 5, detailY, W - 10, detailH, SWP_NOZORDER);
    if (g_hListAllow)
        SetWindowPos(g_hListAllow, nullptr, 5, innerTop, W - 10, H - innerTop - 45, SWP_NOZORDER);
    if (g_hListBlock)
        SetWindowPos(g_hListBlock, nullptr, 5, innerTop, W - 10, H - innerTop - 45, SWP_NOZORDER);

    HWND hAA = GetDlgItem(hwnd, ID_BTN_ADD_ALLOW), hRA = GetDlgItem(hwnd, ID_BTN_REMOVE_ALLOW);
    HWND hAB = GetDlgItem(hwnd, ID_BTN_ADD_BLOCK), hRB = GetDlgItem(hwnd, ID_BTN_REMOVE_BLOCK);
    HWND hRef = GetDlgItem(hwnd, ID_BTN_REFRESH);
    HWND hLF = GetDlgItem(hwnd, ID_LABEL_FROM), hLT = GetDlgItem(hwnd, ID_LABEL_TO);
    HWND hClear = GetDlgItem(hwnd, ID_BTN_CLEAR_FILTER);

    if (hAA)
        SetWindowPos(hAA, nullptr, 5, btnY, 100, 30, SWP_NOZORDER);
    if (hRA)
        SetWindowPos(hRA, nullptr, 115, btnY, 100, 30, SWP_NOZORDER);
    if (hAB)
        SetWindowPos(hAB, nullptr, 5, btnY, 100, 30, SWP_NOZORDER);
    if (hRB)
        SetWindowPos(hRB, nullptr, 115, btnY, 100, 30, SWP_NOZORDER);
    if (hRef)
        SetWindowPos(hRef, nullptr, W - 110, 3, 100, 24, SWP_NOZORDER);

    int fy = statH + 4;
    if (g_hFilterVerdict)
        SetWindowPos(g_hFilterVerdict, nullptr, 5, fy, 130, 200, SWP_NOZORDER);
    if (g_hFilterClass)
        SetWindowPos(g_hFilterClass, nullptr, 145, fy, 130, 200, SWP_NOZORDER);
    if (hLF)
        SetWindowPos(hLF, nullptr, 285, fy + 3, 35, 20, SWP_NOZORDER);
    if (g_hFilterDateFrom)
        SetWindowPos(g_hFilterDateFrom, nullptr, 320, fy, 100, 22, SWP_NOZORDER);
    if (hLT)
        SetWindowPos(hLT, nullptr, 428, fy + 3, 20, 20, SWP_NOZORDER);
    if (g_hFilterDateTo)
        SetWindowPos(g_hFilterDateTo, nullptr, 450, fy, 100, 22, SWP_NOZORDER);
    if (g_hToggleCurrent)
        SetWindowPos(g_hToggleCurrent, nullptr, 560, fy + 2, 140, 22, SWP_NOZORDER);
    if (hClear)
        SetWindowPos(hClear, nullptr, 710, fy, 80, 24, SWP_NOZORDER);

    InvalidateRect(hwnd, nullptr, FALSE);
}

// ─── Tab Switching ────────────────────────────────────────────────────────────

void switchTab(int tab)
{
    g_activeTab = tab;
    ShowWindow(g_hListEvents, tab == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hDetail, tab == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hListAllow, tab == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(g_hWnd, ID_BTN_ADD_ALLOW), tab == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(g_hWnd, ID_BTN_REMOVE_ALLOW), tab == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hListBlock, tab == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(g_hWnd, ID_BTN_ADD_BLOCK), tab == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(g_hWnd, ID_BTN_REMOVE_BLOCK), tab == 2 ? SW_SHOW : SW_HIDE);
    // Filter bar only on events tab
    int fs = (tab == 0) ? SW_SHOW : SW_HIDE;
    ShowWindow(g_hFilterVerdict, fs);
    ShowWindow(g_hFilterClass, fs);
    ShowWindow(g_hFilterDateFrom, fs);
    ShowWindow(g_hFilterDateTo, fs);
    ShowWindow(g_hToggleCurrent, fs);
    ShowWindow(GetDlgItem(g_hWnd, ID_LABEL_FROM), fs);
    ShowWindow(GetDlgItem(g_hWnd, ID_LABEL_TO), fs);
    ShowWindow(GetDlgItem(g_hWnd, ID_BTN_CLEAR_FILTER), fs);
}

// ─── Add Device Dialog ────────────────────────────────────────────────────────

struct AddDialogParams
{
    std::wstring vidPid, note;
};
HWND g_hDlgVidPid = nullptr, g_hDlgNote = nullptr;

LRESULT CALLBACK addDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static AddDialogParams *p = nullptr;
    if (msg == WM_CREATE)
    {
        CreateWindowW(L"STATIC", L"VID:PID (e.g. 0781:5577):", WS_CHILD | WS_VISIBLE, 10, 10, 260, 20, hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
        g_hDlgVidPid = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_UPPERCASE, 10, 32, 260, 24, hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
        CreateWindowW(L"STATIC", L"Note (optional):", WS_CHILD | WS_VISIBLE, 10, 65, 260, 20, hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
        g_hDlgNote = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER, 10, 87, 260, 24, hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
        CreateWindowW(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 10, 125, 120, 30, hwnd, (HMENU)IDOK, GetModuleHandleW(nullptr), nullptr);
        CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE, 150, 125, 120, 30, hwnd, (HMENU)IDCANCEL, GetModuleHandleW(nullptr), nullptr);
        p = reinterpret_cast<AddDialogParams *>(reinterpret_cast<CREATESTRUCTW *>(lParam)->lpCreateParams);
    }
    else if (msg == WM_COMMAND)
    {
        wchar_t buf[256];
        if (LOWORD(wParam) == IDOK)
        {
            GetWindowTextW(g_hDlgVidPid, buf, 64);
            p->vidPid = buf;
            GetWindowTextW(g_hDlgNote, buf, 256);
            p->note = buf;
            DestroyWindow(hwnd);
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            p->vidPid.clear();
            DestroyWindow(hwnd);
        }
    }
    else if (msg == WM_DESTROY)
        PostQuitMessage(0);
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool showAddDialog(HWND parent, std::wstring &vidPid, std::wstring &note)
{
    WNDCLASSW wc{};
    wc.lpfnWndProc = addDialogProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"USBAddDialog";
    RegisterClassW(&wc);
    AddDialogParams params;
    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"USBAddDialog", L"Add Device",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, 100, 100, 300, 210,
                                parent, nullptr, GetModuleHandleW(nullptr), &params);
    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    vidPid = params.vidPid;
    note = params.note;
    return !vidPid.empty();
}

// ─── Control Creation ─────────────────────────────────────────────────────────

void createControls(HWND hwnd)
{
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    RECT rc;
    GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    // Stat bar
    g_hStatClean = CreateWindowW(L"STATIC", L"Clean: 0", WS_CHILD | WS_VISIBLE, 5, 5, 140, 20, hwnd, (HMENU)ID_STAT_CLEAN, hInst, nullptr);
    g_hStatSusp = CreateWindowW(L"STATIC", L"Suspicious: 0", WS_CHILD | WS_VISIBLE, 155, 5, 155, 20, hwnd, (HMENU)ID_STAT_SUSPICIOUS, hInst, nullptr);
    g_hStatAlert = CreateWindowW(L"STATIC", L"Alert: 0", WS_CHILD | WS_VISIBLE, 320, 5, 110, 20, hwnd, (HMENU)ID_STAT_ALERT, hInst, nullptr);
    g_hStatBlock = CreateWindowW(L"STATIC", L"Blocked: 0", WS_CHILD | WS_VISIBLE, 440, 5, 120, 20, hwnd, (HMENU)ID_STAT_BLOCKED, hInst, nullptr);
    CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, W - 110, 2, 100, 24, hwnd, (HMENU)ID_BTN_REFRESH, hInst, nullptr);

    // Filter bar
    g_hFilterVerdict = CreateWindowW(L"COMBOBOX", nullptr, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 5, 30, 130, 200, hwnd, (HMENU)ID_FILTER_VERDICT, hInst, nullptr);
    for (auto s : {L"All Verdicts", L"CLEAN", L"SUSPICIOUS", L"ALERT", L"BLOCKED"})
        SendMessageW(g_hFilterVerdict, CB_ADDSTRING, 0, (LPARAM)s);
    SendMessageW(g_hFilterVerdict, CB_SETCURSEL, 0, 0);

    g_hFilterClass = CreateWindowW(L"COMBOBOX", nullptr, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 145, 30, 130, 200, hwnd, (HMENU)ID_FILTER_CLASS, hInst, nullptr);
    for (auto s : {L"All Classes", L"HID", L"Mass Storage", L"CDC/Serial", L"Composite"})
        SendMessageW(g_hFilterClass, CB_ADDSTRING, 0, (LPARAM)s);
    SendMessageW(g_hFilterClass, CB_SETCURSEL, 0, 0);

    CreateWindowW(L"STATIC", L"From:", WS_CHILD | WS_VISIBLE, 285, 33, 35, 20, hwnd, (HMENU)ID_LABEL_FROM, hInst, nullptr);
    g_hFilterDateFrom = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER, 320, 30, 100, 22, hwnd, (HMENU)ID_FILTER_DATE_FROM, hInst, nullptr);
    CreateWindowW(L"STATIC", L"To:", WS_CHILD | WS_VISIBLE, 428, 33, 20, 20, hwnd, (HMENU)ID_LABEL_TO, hInst, nullptr);
    g_hFilterDateTo = CreateWindowW(L"EDIT", todayStr().c_str(), WS_CHILD | WS_VISIBLE | WS_BORDER, 450, 30, 100, 22, hwnd, (HMENU)ID_FILTER_DATE_TO, hInst, nullptr);
    g_hToggleCurrent = CreateWindowW(L"BUTTON", L"Current Only", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 560, 32, 140, 22, hwnd, (HMENU)ID_TOGGLE_CURRENT, hInst, nullptr);
    CreateWindowW(L"BUTTON", L"Clear", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 710, 30, 80, 24, hwnd, (HMENU)ID_BTN_CLEAR_FILTER, hInst, nullptr);

    // Tab control
    g_hTab = CreateWindowExW(0, WC_TABCONTROLW, nullptr, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 58, W, H - 58, hwnd, (HMENU)ID_TAB, hInst, nullptr);
    TCITEMW ti{};
    ti.mask = TCIF_TEXT;
    ti.pszText = (LPWSTR)L"  Live Events  ";
    TabCtrl_InsertItem(g_hTab, 0, &ti);
    ti.pszText = (LPWSTR)L"  Allow List  ";
    TabCtrl_InsertItem(g_hTab, 1, &ti);
    ti.pszText = (LPWSTR)L"  Block List  ";
    TabCtrl_InsertItem(g_hTab, 2, &ti);

    // Events list
    g_hListEvents = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr, WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL, 5, 90, W - 10, 300, hwnd, (HMENU)ID_LIST_EVENTS, hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_hListEvents, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    addColumn(g_hListEvents, 0, L"Timestamp", 145);
    addColumn(g_hListEvents, 1, L"Description", 200);
    addColumn(g_hListEvents, 2, L"Manufacturer", 150);
    addColumn(g_hListEvents, 3, L"VID:PID", 90);
    addColumn(g_hListEvents, 4, L"Class", 100);
    addColumn(g_hListEvents, 5, L"Verdict", 90);
    addColumn(g_hListEvents, 6, L"Reasons", 350);

    // Detail box
    g_hDetail = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL, 5, 400, W - 10, 150, hwnd, (HMENU)ID_DETAIL_BOX, hInst, nullptr);

    // Allow list
    g_hListAllow = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr, WS_CHILD | LVS_REPORT | LVS_SINGLESEL, 5, 90, W - 10, 300, hwnd, (HMENU)ID_LIST_ALLOW, hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_hListAllow, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    addColumn(g_hListAllow, 0, L"VID:PID", 120);
    addColumn(g_hListAllow, 1, L"Note", 500);
    CreateWindowW(L"BUTTON", L"+ Add", WS_CHILD | BS_PUSHBUTTON, 5, 400, 100, 30, hwnd, (HMENU)ID_BTN_ADD_ALLOW, hInst, nullptr);
    CreateWindowW(L"BUTTON", L"- Remove", WS_CHILD | BS_PUSHBUTTON, 115, 400, 100, 30, hwnd, (HMENU)ID_BTN_REMOVE_ALLOW, hInst, nullptr);

    // Block list
    g_hListBlock = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr, WS_CHILD | LVS_REPORT | LVS_SINGLESEL, 5, 90, W - 10, 300, hwnd, (HMENU)ID_LIST_BLOCK, hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_hListBlock, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    addColumn(g_hListBlock, 0, L"VID:PID", 120);
    addColumn(g_hListBlock, 1, L"Note", 500);
    CreateWindowW(L"BUTTON", L"+ Add", WS_CHILD | BS_PUSHBUTTON, 5, 400, 100, 30, hwnd, (HMENU)ID_BTN_ADD_BLOCK, hInst, nullptr);
    CreateWindowW(L"BUTTON", L"- Remove", WS_CHILD | BS_PUSHBUTTON, 115, 400, 100, 30, hwnd, (HMENU)ID_BTN_REMOVE_BLOCK, hInst, nullptr);

    g_splitterY = H / 2 + 20;
    switchTab(0);
}

// ─── Splitter Hit Test ────────────────────────────────────────────────────────

bool isSplitterHit(int x, int y)
{
    if (g_activeTab != 0)
        return false;
    RECT rc;
    GetClientRect(g_hWnd, &rc);
    return (y >= g_splitterY && y < g_splitterY + SPLITTER_H && x >= 5 && x <= rc.right - 5);
}

// ─── Main Window Procedure ────────────────────────────────────────────────────

LRESULT CALLBACK mainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {

    case WM_CREATE:
        g_hWnd = hwnd;
        InitCommonControls();
        createControls(hwnd);
        doRefresh(true);
        SetTimer(hwnd, REFRESH_TIMER_ID, REFRESH_INTERVAL, nullptr);
        break;

    case WM_TIMER:
        if (wParam == REFRESH_TIMER_ID)
            doRefresh();
        break;

    case WM_SIZE:
        relayout(hwnd);
        break;

    case WM_SETCURSOR:
    {
        POINT pt;
        GetCursorPos(&pt);
        ScreenToClient(hwnd, &pt);
        if (isSplitterHit(pt.x, pt.y))
        {
            SetCursor(LoadCursorW(nullptr, IDC_SIZENS));
            return TRUE;
        }
        break;
    }

    case WM_LBUTTONDOWN:
    {
        int x = LOWORD(lParam), y = HIWORD(lParam);
        if (isSplitterHit(x, y))
        {
            g_dragging = true;
            g_dragOffsetY = y - g_splitterY;
            SetCapture(hwnd);
        }
        break;
    }

    case WM_MOUSEMOVE:
    {
        int x = LOWORD(lParam), y = HIWORD(lParam);
        if (g_dragging)
        {
            g_splitterY = y - g_dragOffsetY;
            relayout(hwnd);
        }
        else if (isSplitterHit(x, y))
            SetCursor(LoadCursorW(nullptr, IDC_SIZENS));
        break;
    }

    case WM_LBUTTONUP:
        if (g_dragging)
        {
            g_dragging = false;
            ReleaseCapture();
        }
        break;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        if (g_activeTab == 0)
        {
            RECT rc;
            GetClientRect(hwnd, &rc);
            RECT sr = {5, g_splitterY, rc.right - 5, g_splitterY + SPLITTER_H};
            HBRUSH hBr = CreateSolidBrush(RGB(210, 210, 210));
            FillRect(hdc, &sr, hBr);
            DeleteObject(hBr);
            DrawEdge(hdc, &sr, EDGE_RAISED, BF_RECT);
        }
        EndPaint(hwnd, &ps);
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_BTN_REFRESH:
            doRefresh(true);
            break;

        case ID_FILTER_VERDICT:
        case ID_FILTER_CLASS:
            if (HIWORD(wParam) == CBN_SELCHANGE)
                populateEvents();
            break;

        case ID_FILTER_DATE_FROM:
        case ID_FILTER_DATE_TO:
            if (HIWORD(wParam) == EN_CHANGE)
                populateEvents();
            break;

        case ID_TOGGLE_CURRENT:
            populateEvents();
            break;

        case ID_BTN_CLEAR_FILTER:
            SendMessageW(g_hFilterVerdict, CB_SETCURSEL, 0, 0);
            SendMessageW(g_hFilterClass, CB_SETCURSEL, 0, 0);
            SetWindowTextW(g_hFilterDateFrom, L"");
            SetWindowTextW(g_hFilterDateTo, todayStr().c_str());
            SendMessageW(g_hToggleCurrent, BM_SETCHECK, BST_UNCHECKED, 0);
            populateEvents();
            break;

        case ID_BTN_ADD_ALLOW:
        {
            std::wstring v, n;
            if (showAddDialog(hwnd, v, n))
            {
                ListEntry e;
                e.vidPid = v;
                e.note = n;
                g_allowList.push_back(e);
                saveListFile(ALLOW_PATH, g_allowList, "allowlist");
                populateAllowList();
            }
            break;
        }
        case ID_BTN_REMOVE_ALLOW:
        {
            int sel = ListView_GetNextItem(g_hListAllow, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < (int)g_allowList.size())
            {
                g_allowList.erase(g_allowList.begin() + sel);
                saveListFile(ALLOW_PATH, g_allowList, "allowlist");
                populateAllowList();
            }
            break;
        }
        case ID_BTN_ADD_BLOCK:
        {
            std::wstring v, n;
            if (showAddDialog(hwnd, v, n))
            {
                ListEntry e;
                e.vidPid = v;
                e.note = n;
                g_blockList.push_back(e);
                saveListFile(BLOCK_PATH, g_blockList, "blocklist");
                populateBlockList();
            }
            break;
        }
        case ID_BTN_REMOVE_BLOCK:
        {
            int sel = ListView_GetNextItem(g_hListBlock, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < (int)g_blockList.size())
            {
                g_blockList.erase(g_blockList.begin() + sel);
                saveListFile(BLOCK_PATH, g_blockList, "blocklist");
                populateBlockList();
            }
            break;
        }
        }
        break;

    case WM_NOTIFY:
    {
        NMHDR *nm = reinterpret_cast<NMHDR *>(lParam);
        if (nm->hwndFrom == g_hTab && nm->code == TCN_SELCHANGE)
        {
            switchTab(TabCtrl_GetCurSel(g_hTab));
            relayout(hwnd);
        }
        if (nm->hwndFrom == g_hListEvents && nm->code == LVN_ITEMCHANGED)
        {
            NMLISTVIEW *nmlv = reinterpret_cast<NMLISTVIEW *>(lParam);
            if (nmlv->uNewState & LVIS_SELECTED)
                showEventDetail(nmlv->iItem);
        }
        break;
    }

    case WM_DESTROY:
        KillTimer(hwnd, REFRESH_TIMER_ID);
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow)
{
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = mainWndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"USBMonitorUI";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, L"USBMonitorUI",
                                L"USB Descriptor Monitor - Layer 1",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1100, 700,
                                nullptr, nullptr, hInst, nullptr);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}