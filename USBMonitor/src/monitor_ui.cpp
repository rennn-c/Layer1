// monitor_ui.cpp
// ─────────────────────────────────────────────────────────────────────────────
// USB Descriptor Monitor — Standalone Desktop UI
// Reads from C:\ProgramData\USBMonitor\ (written by the service)
// Provides live event view, descriptor details, and allow/block list management
// Compiled separately into USBMonitorUI.exe
// ─────────────────────────────────────────────────────────────────────────────

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>  // Core Windows API
#include <commctrl.h> // ListView, TabControl, common controls
#include <shellapi.h> // Shell_NotifyIcon (optional future use)
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <iomanip>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' \
    name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
    processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ─── Constants ───────────────────────────────────────────────────────────────

#define DATA_DIR L"C:\\ProgramData\\USBMonitor"
#define CSV_PATH L"C:\\ProgramData\\USBMonitor\\usb_descriptors.csv"
#define ALLOW_PATH L"C:\\ProgramData\\USBMonitor\\allowlist.txt"
#define BLOCK_PATH L"C:\\ProgramData\\USBMonitor\\blocklist.txt"

#define REFRESH_TIMER_ID 1
#define REFRESH_INTERVAL 2000 // Check for file changes every 2 seconds

// Control IDs
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

// ─── Data Structures ─────────────────────────────────────────────────────────

// Represents one row from usb_descriptors.csv
struct USBEvent
{
    std::wstring timestamp;
    std::wstring instanceId;
    std::wstring vendorId;
    std::wstring productId;
    std::wstring description;
    std::wstring manufacturer;
    std::wstring product;
    std::wstring serialNumber;
    std::wstring deviceClass;
    std::wstring service;
    std::wstring location;
    std::wstring hasHID;
    std::wstring hasMassStorage;
    std::wstring hasCDC;
    std::wstring hasVendorClass;
    std::wstring isComposite;
    std::wstring verdict;
    std::wstring reasons;
};

// Represents one entry in allow/block list file
struct ListEntry
{
    std::wstring vidPid; // e.g. "0781:5577"
    std::wstring note;   // comment after #
};

// ─── Globals ─────────────────────────────────────────────────────────────────

HWND g_hWnd = nullptr;        // Main window handle
HWND g_hTab = nullptr;        // Tab control handle
HWND g_hListEvents = nullptr; // Events ListView handle
HWND g_hListAllow = nullptr;  // Allowlist ListView handle
HWND g_hListBlock = nullptr;  // Blocklist ListView handle
HWND g_hDetail = nullptr;     // Detail text box handle
HWND g_hStatClean = nullptr;  // Stat label: CLEAN count
HWND g_hStatSusp = nullptr;   // Stat label: SUSPICIOUS count
HWND g_hStatAlert = nullptr;  // Stat label: ALERT count
HWND g_hStatBlock = nullptr;  // Stat label: BLOCKED count

std::vector<USBEvent> g_events;     // All loaded CSV events
std::vector<ListEntry> g_allowList; // Loaded allowlist entries
std::vector<ListEntry> g_blockList; // Loaded blocklist entries
int g_activeTab = 0;                // Currently selected tab index

// ─── File Time Tracking ───────────────────────────────────────────────────────
// Stores last known file modification times to avoid unnecessary redraws.
// The UI only reloads data when a file actually changes on disk.

FILETIME g_lastCSVTime{};   // Last modified time of usb_descriptors.csv
FILETIME g_lastAllowTime{}; // Last modified time of allowlist.txt
FILETIME g_lastBlockTime{}; // Last modified time of blocklist.txt

// Returns the last-modified FILETIME of a file on disk.
// Returns zeroed FILETIME if the file cannot be opened.
FILETIME getFileTime(const std::wstring &path)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    FILETIME ft{};
    if (h != INVALID_HANDLE_VALUE)
    {
        GetFileTime(h, nullptr, nullptr, &ft); // Get last-write time
        CloseHandle(h);
    }
    return ft;
}

// ─── String Utilities ─────────────────────────────────────────────────────────

// Converts a narrow UTF-8 string to a wide string
std::wstring strToWstr(const std::string &s)
{
    if (s.empty())
        return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

// Removes surrounding double-quotes from a CSV field and unescapes doubled quotes
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
        {
            out += r[i];
        }
    }
    return out;
}

// Splits one CSV line into a vector of field strings,
// correctly handling quoted fields that may contain commas
std::vector<std::wstring> splitCSV(const std::wstring &line)
{
    std::vector<std::wstring> fields;
    std::wstring field;
    bool inQuotes = false;

    for (size_t i = 0; i < line.size(); i++)
    {
        wchar_t c = line[i];
        if (c == L'"')
        {
            if (inQuotes && i + 1 < line.size() && line[i + 1] == L'"')
            {
                field += L'"';
                i++; // Escaped inner quote
            }
            else
            {
                inQuotes = !inQuotes; // Toggle quoted mode
            }
        }
        else if (c == L',' && !inQuotes)
        {
            fields.push_back(field); // Field boundary
            field.clear();
        }
        else
        {
            field += c;
        }
    }
    fields.push_back(field); // Push last field
    return fields;
}

// ─── File I/O ─────────────────────────────────────────────────────────────────

// Reads all rows from usb_descriptors.csv into g_events vector
void loadCSV()
{
    g_events.clear();
    std::wifstream f(CSV_PATH);
    if (!f)
        return;

    std::wstring line;
    std::getline(f, line); // Skip header row

    while (std::getline(f, line))
    {
        if (line.empty())
            continue;
        auto fields = splitCSV(line);
        if (fields.size() < 21)
            continue; // Skip malformed rows

        USBEvent e;
        e.timestamp = trimField(fields[0]);
        e.instanceId = trimField(fields[1]);
        e.vendorId = trimField(fields[2]);
        e.productId = trimField(fields[3]);
        e.description = trimField(fields[4]);
        e.manufacturer = trimField(fields[5]);
        e.product = trimField(fields[6]);
        e.serialNumber = trimField(fields[7]);
        e.deviceClass = trimField(fields[8]);
        e.service = trimField(fields[9]);
        e.location = trimField(fields[10]);
        e.hasHID = trimField(fields[11]);
        e.hasMassStorage = trimField(fields[12]);
        e.hasCDC = trimField(fields[13]);
        e.hasVendorClass = trimField(fields[14]);
        e.isComposite = trimField(fields[15]);
        e.verdict = trimField(fields[19]);
        e.reasons = trimField(fields[20]);
        g_events.push_back(e);
    }
}

// Reads allowlist.txt or blocklist.txt into a ListEntry vector.
// Lines starting with # are treated as comments and skipped.
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
        auto hash = line.find(L'#');
        if (hash != std::wstring::npos)
        {
            note = line.substr(hash + 1); // Everything after # is the note
            line = line.substr(0, hash);
        }
        // Trim leading whitespace
        auto start = line.find_first_not_of(L" \t\r\n");
        if (start == std::wstring::npos)
            continue;
        line = line.substr(start);
        // Trim trailing whitespace
        auto end = line.find_last_not_of(L" \t\r\n");
        if (end != std::wstring::npos)
            line = line.substr(0, end + 1);
        if (line.empty())
            continue;

        // Trim leading whitespace from note
        auto ns = note.find_first_not_of(L" \t");
        if (ns != std::wstring::npos)
            note = note.substr(ns);

        ListEntry entry;
        entry.vidPid = line;
        entry.note = note;
        out.push_back(entry);
    }
}

// Writes a ListEntry vector back to a list file with a header comment block
void saveListFile(const std::wstring &path,
                  const std::vector<ListEntry> &entries,
                  const std::string &listName)
{
    std::wofstream f(path);
    f << L"# USB Monitor - " << strToWstr(listName) << L"\n";
    f << L"# Format: VID:PID  # optional note\n";
    f << L"# Example: 046D:C52B  # Logitech USB Receiver\n\n";
    for (const auto &e : entries)
    {
        f << e.vidPid;
        if (!e.note.empty())
            f << L"  # " << e.note;
        f << L"\n";
    }
}

// ─── Stats ────────────────────────────────────────────────────────────────────

// Counts events by verdict and updates the four stat labels at the top
void updateStats()
{
    int clean = 0, suspicious = 0, alert = 0, blocked = 0;
    for (const auto &e : g_events)
    {
        if (e.verdict == L"CLEAN")
            clean++;
        else if (e.verdict == L"SUSPICIOUS")
            suspicious++;
        else if (e.verdict == L"ALERT")
            alert++;
        else if (e.verdict == L"BLOCKED")
            blocked++;
    }
    SetWindowTextW(g_hStatClean, (L"Clean: " + std::to_wstring(clean)).c_str());
    SetWindowTextW(g_hStatSusp, (L"Suspicious: " + std::to_wstring(suspicious)).c_str());
    SetWindowTextW(g_hStatAlert, (L"Alert: " + std::to_wstring(alert)).c_str());
    SetWindowTextW(g_hStatBlock, (L"Blocked: " + std::to_wstring(blocked)).c_str());
}

// ─── ListView Helpers ─────────────────────────────────────────────────────────

// Adds a column with a title and pixel width to a ListView control
void addColumn(HWND hList, int col, const wchar_t *title, int width)
{
    LVCOLUMNW lvc{};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.cx = width;
    lvc.pszText = (LPWSTR)title;
    lvc.iSubItem = col;
    ListView_InsertColumn(hList, col, &lvc);
}

// Inserts a new row into a ListView and fills all column values
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

// Clears and repopulates the Events ListView from the g_events vector
void populateEvents()
{
    ListView_DeleteAllItems(g_hListEvents);
    for (int i = 0; i < (int)g_events.size(); i++)
    {
        const auto &e = g_events[i];
        insertRow(g_hListEvents, i, {e.timestamp, e.description, e.manufacturer, e.vendorId + L":" + e.productId, e.deviceClass, e.verdict, e.reasons});
    }
}

// Clears and repopulates the Allowlist ListView from g_allowList
void populateAllowList()
{
    ListView_DeleteAllItems(g_hListAllow);
    for (int i = 0; i < (int)g_allowList.size(); i++)
        insertRow(g_hListAllow, i, {g_allowList[i].vidPid, g_allowList[i].note});
}

// Clears and repopulates the Blocklist ListView from g_blockList
void populateBlockList()
{
    ListView_DeleteAllItems(g_hListBlock);
    for (int i = 0; i < (int)g_blockList.size(); i++)
        insertRow(g_hListBlock, i, {g_blockList[i].vidPid, g_blockList[i].note});
}

// Builds and displays full descriptor details for the selected event
// in the read-only detail text box below the events list
void showEventDetail(int index)
{
    if (index < 0 || index >= (int)g_events.size())
        return;
    const auto &e = g_events[index];

    std::wostringstream ss;
    ss << L"=== Device Descriptor ===\r\n";
    ss << L"Timestamp:    " << e.timestamp << L"\r\n";
    ss << L"Description:  " << e.description << L"\r\n";
    ss << L"Manufacturer: " << e.manufacturer << L"\r\n";
    ss << L"Product:      " << e.product << L"\r\n";
    ss << L"Serial:       " << e.serialNumber << L"\r\n";
    ss << L"Class:        " << e.deviceClass << L"\r\n";
    ss << L"Service:      " << e.service << L"\r\n";
    ss << L"Location:     " << e.location << L"\r\n";
    ss << L"VendorID:     " << e.vendorId << L"\r\n";
    ss << L"ProductID:    " << e.productId << L"\r\n";
    ss << L"\r\n=== Interfaces ===\r\n";
    ss << L"HID:          " << (e.hasHID == L"1" ? L"YES" : L"no") << L"\r\n";
    ss << L"MassStorage:  " << (e.hasMassStorage == L"1" ? L"YES" : L"no") << L"\r\n";
    ss << L"CDC/Serial:   " << (e.hasCDC == L"1" ? L"YES" : L"no") << L"\r\n";
    ss << L"VendorClass:  " << (e.hasVendorClass == L"1" ? L"YES" : L"no") << L"\r\n";
    ss << L"Composite:    " << (e.isComposite == L"1" ? L"YES" : L"no") << L"\r\n";
    ss << L"\r\n=== Layer 1 Verdict ===\r\n";
    ss << L"Verdict:  " << e.verdict << L"\r\n";
    ss << L"Reasons:  " << e.reasons << L"\r\n";
    ss << L"\r\nInstance ID:\r\n"
       << e.instanceId << L"\r\n";

    SetWindowTextW(g_hDetail, ss.str().c_str());
}

// ─── Refresh Logic ────────────────────────────────────────────────────────────

// Checks file modification times and only reloads/redraws what actually changed.
// Pass force=true to reload everything regardless (used on startup and manual refresh).
void doRefresh(bool force = false)
{
    FILETIME csvTime = getFileTime(CSV_PATH);
    FILETIME allowTime = getFileTime(ALLOW_PATH);
    FILETIME blockTime = getFileTime(BLOCK_PATH);

    // CompareFileTime returns 0 if times are equal — nonzero means file changed
    bool csvChanged = CompareFileTime(&csvTime, &g_lastCSVTime) != 0;
    bool allowChanged = CompareFileTime(&allowTime, &g_lastAllowTime) != 0;
    bool blockChanged = CompareFileTime(&blockTime, &g_lastBlockTime) != 0;

    if (force || csvChanged)
    {
        loadCSV();
        populateEvents();
        updateStats();
        g_lastCSVTime = csvTime; // Update tracked time
    }
    if (force || allowChanged)
    {
        loadListFile(ALLOW_PATH, g_allowList);
        populateAllowList();
        g_lastAllowTime = allowTime;
    }
    if (force || blockChanged)
    {
        loadListFile(BLOCK_PATH, g_blockList);
        populateBlockList();
        g_lastBlockTime = blockTime;
    }
}

// ─── Tab Switching ────────────────────────────────────────────────────────────

// Shows controls for the selected tab and hides controls for all others
void switchTab(int tab)
{
    g_activeTab = tab;

    // Tab 0: Live Events — show event list and detail box
    ShowWindow(g_hListEvents, tab == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hDetail, tab == 0 ? SW_SHOW : SW_HIDE);

    // Tab 1: Allow List — show allow list and its buttons
    ShowWindow(g_hListAllow, tab == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(g_hWnd, ID_BTN_ADD_ALLOW), tab == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(g_hWnd, ID_BTN_REMOVE_ALLOW), tab == 1 ? SW_SHOW : SW_HIDE);

    // Tab 2: Block List — show block list and its buttons
    ShowWindow(g_hListBlock, tab == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(g_hWnd, ID_BTN_ADD_BLOCK), tab == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(g_hWnd, ID_BTN_REMOVE_BLOCK), tab == 2 ? SW_SHOW : SW_HIDE);
}

// ─── Add Device Dialog ────────────────────────────────────────────────────────

// Holds output from the add-device input dialog
struct AddDialogParams
{
    std::wstring vidPid; // VID:PID entered by user
    std::wstring note;   // Optional note entered by user
};

HWND g_hDlgVidPid = nullptr; // Edit control: VID:PID input
HWND g_hDlgNote = nullptr;   // Edit control: note input

// Window procedure for the small "Add Device" input dialog
LRESULT CALLBACK addDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static AddDialogParams *params = nullptr;

    switch (msg)
    {
    case WM_CREATE:
    {
        CreateWindowW(L"STATIC", L"VID:PID (e.g. 0781:5577):",
                      WS_CHILD | WS_VISIBLE, 10, 10, 260, 20, hwnd, nullptr,
                      GetModuleHandleW(nullptr), nullptr);
        g_hDlgVidPid = CreateWindowW(L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_BORDER | ES_UPPERCASE,
                                     10, 32, 260, 24, hwnd, nullptr,
                                     GetModuleHandleW(nullptr), nullptr);
        CreateWindowW(L"STATIC", L"Note (optional):",
                      WS_CHILD | WS_VISIBLE, 10, 65, 260, 20, hwnd, nullptr,
                      GetModuleHandleW(nullptr), nullptr);
        g_hDlgNote = CreateWindowW(L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER,
                                   10, 87, 260, 24, hwnd, nullptr,
                                   GetModuleHandleW(nullptr), nullptr);
        CreateWindowW(L"BUTTON", L"OK",
                      WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                      10, 125, 120, 30, hwnd, (HMENU)IDOK,
                      GetModuleHandleW(nullptr), nullptr);
        CreateWindowW(L"BUTTON", L"Cancel",
                      WS_CHILD | WS_VISIBLE,
                      150, 125, 120, 30, hwnd, (HMENU)IDCANCEL,
                      GetModuleHandleW(nullptr), nullptr);
        params = reinterpret_cast<AddDialogParams *>(
            reinterpret_cast<CREATESTRUCTW *>(lParam)->lpCreateParams);
        break;
    }
    case WM_COMMAND:
    {
        if (LOWORD(wParam) == IDOK)
        {
            wchar_t buf[256];
            GetWindowTextW(g_hDlgVidPid, buf, 64);
            params->vidPid = buf;
            GetWindowTextW(g_hDlgNote, buf, 256);
            params->note = buf;
            DestroyWindow(hwnd);
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            params->vidPid.clear();
            DestroyWindow(hwnd);
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// Shows the Add Device dialog modally and returns true if user confirmed
bool showAddDialog(HWND parent, std::wstring &vidPid, std::wstring &note)
{
    WNDCLASSW wc{};
    wc.lpfnWndProc = addDialogProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"USBAddDialog";
    RegisterClassW(&wc); // Safe to call multiple times — will fail silently if already registered

    AddDialogParams params;
    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME, L"USBAddDialog", L"Add Device",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        100, 100, 300, 210,
        parent, nullptr, GetModuleHandleW(nullptr), &params);
    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    // Run a local message loop until dialog is destroyed (PostQuitMessage)
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    vidPid = params.vidPid;
    note = params.note;
    return !vidPid.empty(); // False if user cancelled
}

// ─── Window Creation ──────────────────────────────────────────────────────────

// Creates all child controls for the main window on startup
void createControls(HWND hwnd)
{
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    RECT rc;
    GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    // ── Stat bar (top strip) ──────────────────────────────────────────────────
    g_hStatClean = CreateWindowW(L"STATIC", L"Clean: 0",
                                 WS_CHILD | WS_VISIBLE, 5, 6, 150, 22, hwnd,
                                 (HMENU)ID_STAT_CLEAN, hInst, nullptr);
    g_hStatSusp = CreateWindowW(L"STATIC", L"Suspicious: 0",
                                WS_CHILD | WS_VISIBLE, 165, 6, 160, 22, hwnd,
                                (HMENU)ID_STAT_SUSPICIOUS, hInst, nullptr);
    g_hStatAlert = CreateWindowW(L"STATIC", L"Alert: 0",
                                 WS_CHILD | WS_VISIBLE, 335, 6, 120, 22, hwnd,
                                 (HMENU)ID_STAT_ALERT, hInst, nullptr);
    g_hStatBlock = CreateWindowW(L"STATIC", L"Blocked: 0",
                                 WS_CHILD | WS_VISIBLE, 465, 6, 130, 22, hwnd,
                                 (HMENU)ID_STAT_BLOCKED, hInst, nullptr);

    // Refresh button (top right)
    CreateWindowW(L"BUTTON", L"Refresh",
                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                  W - 110, 3, 100, 26, hwnd,
                  (HMENU)ID_BTN_REFRESH, hInst, nullptr);

    // ── Tab control ───────────────────────────────────────────────────────────
    g_hTab = CreateWindowExW(0, WC_TABCONTROLW, nullptr,
                             WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                             0, 34, W, H - 34, hwnd,
                             (HMENU)ID_TAB, hInst, nullptr);

    TCITEMW ti{};
    ti.mask = TCIF_TEXT;
    ti.pszText = (LPWSTR)L"  Live Events  ";
    TabCtrl_InsertItem(g_hTab, 0, &ti);
    ti.pszText = (LPWSTR)L"  Allow List  ";
    TabCtrl_InsertItem(g_hTab, 1, &ti);
    ti.pszText = (LPWSTR)L"  Block List  ";
    TabCtrl_InsertItem(g_hTab, 2, &ti);

    // Layout calculations
    int tabH = 30;
    int listTop = 34 + tabH + 5;
    int listH = H - listTop - 185;
    int detailTop = listTop + listH + 5;
    int detailH = 160;
    int btnY = detailTop;

    // ── Events ListView (Tab 0) ───────────────────────────────────────────────
    g_hListEvents = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr,
                                    WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                    5, listTop, W - 10, listH, hwnd,
                                    (HMENU)ID_LIST_EVENTS, hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_hListEvents,
                                      LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    addColumn(g_hListEvents, 0, L"Timestamp", 145);
    addColumn(g_hListEvents, 1, L"Description", 200);
    addColumn(g_hListEvents, 2, L"Manufacturer", 150);
    addColumn(g_hListEvents, 3, L"VID:PID", 90);
    addColumn(g_hListEvents, 4, L"Class", 100);
    addColumn(g_hListEvents, 5, L"Verdict", 90);
    addColumn(g_hListEvents, 6, L"Reasons", 350);

    // ── Detail box (Tab 0, below events list) ─────────────────────────────────
    g_hDetail = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                                    WS_VSCROLL | ES_AUTOVSCROLL,
                                5, detailTop, W - 10, detailH, hwnd,
                                (HMENU)ID_DETAIL_BOX, hInst, nullptr);

    // ── Allowlist ListView (Tab 1) ────────────────────────────────────────────
    g_hListAllow = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr,
                                   WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                   5, listTop, W - 10, listH, hwnd,
                                   (HMENU)ID_LIST_ALLOW, hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_hListAllow,
                                      LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    addColumn(g_hListAllow, 0, L"VID:PID", 120);
    addColumn(g_hListAllow, 1, L"Note", 500);

    CreateWindowW(L"BUTTON", L"+ Add",
                  WS_CHILD | BS_PUSHBUTTON,
                  5, btnY, 100, 30, hwnd,
                  (HMENU)ID_BTN_ADD_ALLOW, hInst, nullptr);
    CreateWindowW(L"BUTTON", L"- Remove",
                  WS_CHILD | BS_PUSHBUTTON,
                  115, btnY, 100, 30, hwnd,
                  (HMENU)ID_BTN_REMOVE_ALLOW, hInst, nullptr);

    // ── Blocklist ListView (Tab 2) ────────────────────────────────────────────
    g_hListBlock = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr,
                                   WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                   5, listTop, W - 10, listH, hwnd,
                                   (HMENU)ID_LIST_BLOCK, hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_hListBlock,
                                      LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    addColumn(g_hListBlock, 0, L"VID:PID", 120);
    addColumn(g_hListBlock, 1, L"Note", 500);

    CreateWindowW(L"BUTTON", L"+ Add",
                  WS_CHILD | BS_PUSHBUTTON,
                  5, btnY, 100, 30, hwnd,
                  (HMENU)ID_BTN_ADD_BLOCK, hInst, nullptr);
    CreateWindowW(L"BUTTON", L"- Remove",
                  WS_CHILD | BS_PUSHBUTTON,
                  115, btnY, 100, 30, hwnd,
                  (HMENU)ID_BTN_REMOVE_BLOCK, hInst, nullptr);

    // Show Tab 0 controls by default
    switchTab(0);
}

// ─── Main Window Procedure ────────────────────────────────────────────────────

LRESULT CALLBACK mainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {

    case WM_CREATE:
        g_hWnd = hwnd;
        InitCommonControls();                                        // Enable visual styles
        createControls(hwnd);                                        // Build all child controls
        doRefresh(true);                                             // Force-load all data on startup
        SetTimer(hwnd, REFRESH_TIMER_ID, REFRESH_INTERVAL, nullptr); // Start auto-check timer
        break;

    case WM_TIMER:
        if (wParam == REFRESH_TIMER_ID)
            doRefresh(); // Check for file changes (no flicker if nothing changed)
        break;

    case WM_SIZE:
    {
        // Reposition and resize all controls when window is resized
        RECT rc;
        GetClientRect(hwnd, &rc);
        int W = rc.right, H = rc.bottom;

        if (g_hTab)
            SetWindowPos(g_hTab, nullptr, 0, 34, W, H - 34, SWP_NOZORDER);

        int tabH = 30;
        int listTop = 34 + tabH + 5;
        int listH = H - listTop - 185;
        int detailTop = listTop + listH + 5;
        int detailH = 160;
        int btnY = detailTop;

        if (g_hListEvents)
            SetWindowPos(g_hListEvents, nullptr, 5, listTop, W - 10, listH, SWP_NOZORDER);
        if (g_hListAllow)
            SetWindowPos(g_hListAllow, nullptr, 5, listTop, W - 10, listH, SWP_NOZORDER);
        if (g_hListBlock)
            SetWindowPos(g_hListBlock, nullptr, 5, listTop, W - 10, listH, SWP_NOZORDER);
        if (g_hDetail)
            SetWindowPos(g_hDetail, nullptr, 5, detailTop, W - 10, detailH, SWP_NOZORDER);

        // Reposition allow/block buttons
        HWND hAA = GetDlgItem(hwnd, ID_BTN_ADD_ALLOW);
        HWND hRA = GetDlgItem(hwnd, ID_BTN_REMOVE_ALLOW);
        HWND hAB = GetDlgItem(hwnd, ID_BTN_ADD_BLOCK);
        HWND hRB = GetDlgItem(hwnd, ID_BTN_REMOVE_BLOCK);
        if (hAA)
            SetWindowPos(hAA, nullptr, 5, btnY, 100, 30, SWP_NOZORDER);
        if (hRA)
            SetWindowPos(hRA, nullptr, 115, btnY, 100, 30, SWP_NOZORDER);
        if (hAB)
            SetWindowPos(hAB, nullptr, 5, btnY, 100, 30, SWP_NOZORDER);
        if (hRB)
            SetWindowPos(hRB, nullptr, 115, btnY, 100, 30, SWP_NOZORDER);

        // Reposition refresh button
        HWND hRef = GetDlgItem(hwnd, ID_BTN_REFRESH);
        if (hRef)
            SetWindowPos(hRef, nullptr, W - 110, 3, 100, 26, SWP_NOZORDER);
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {

        case ID_BTN_REFRESH:
            doRefresh(true); // Force full reload on manual refresh
            break;

        case ID_BTN_ADD_ALLOW:
        {
            std::wstring vidPid, note;
            if (showAddDialog(hwnd, vidPid, note))
            {
                ListEntry e;
                e.vidPid = vidPid;
                e.note = note;
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
            std::wstring vidPid, note;
            if (showAddDialog(hwnd, vidPid, note))
            {
                ListEntry e;
                e.vidPid = vidPid;
                e.note = note;
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
        NMHDR *nmhdr = reinterpret_cast<NMHDR *>(lParam);

        // Tab switched — show/hide relevant controls
        if (nmhdr->hwndFrom == g_hTab && nmhdr->code == TCN_SELCHANGE)
        {
            switchTab(TabCtrl_GetCurSel(g_hTab));
        }

        // Row selected in events list — show full descriptor in detail box
        if (nmhdr->hwndFrom == g_hListEvents && nmhdr->code == LVN_ITEMCHANGED)
        {
            NMLISTVIEW *nmlv = reinterpret_cast<NMLISTVIEW *>(lParam);
            if (nmlv->uNewState & LVIS_SELECTED)
                showEventDetail(nmlv->iItem);
        }
        break;
    }

    case WM_DESTROY:
        KillTimer(hwnd, REFRESH_TIMER_ID); // Stop the auto-refresh timer
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow)
{
    // Register the main window class
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = mainWndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"USBMonitorUI";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_SHIELD); // Shield icon in title bar
    RegisterClassExW(&wc);

    // Create the main window
    HWND hwnd = CreateWindowExW(
        0,
        L"USBMonitorUI",
        L"USB Descriptor Monitor - Layer 1",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1100, 700,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Standard Windows message loop
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}