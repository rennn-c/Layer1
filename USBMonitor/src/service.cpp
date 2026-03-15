#define UNICODE
#define _UNICODE

#include <windows.h>
#include <dbt.h>
#include <initguid.h>
#include <usbiodef.h>
#include <string>
#include <fstream>
#include <ctime>

#include "layer1_descriptor.h"

#pragma comment(lib, "setupapi.lib")

// ─── Config ──────────────────────────────────────────────────────────────────

#define SERVICE_NAME L"USBDescriptorMonitor"
#define SERVICE_DISPLAY L"USB Descriptor Monitor"
#define SERVICE_DESC L"Captures and logs USB device descriptors on plug-in events."
#define LOG_DIR L"C:\\ProgramData\\USBMonitor"

// ─── Globals ─────────────────────────────────────────────────────────────────

SERVICE_STATUS g_Status{};
SERVICE_STATUS_HANDLE g_StatusHandle{};
HANDLE g_StopEvent{};
HWND g_MsgHwnd{};

// ─── Simple Event Logger ──────────────────────────────────────────────────────

static void logEvent(const std::string &msg)
{
    CreateDirectoryW(LOG_DIR, nullptr);

    std::ofstream f(L"C:\\ProgramData\\USBMonitor\\service_events.txt",
                    std::ios::app);
    if (!f)
        return;

    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    char ts[32];
    strftime(ts, sizeof(ts), "[%Y-%m-%d %H:%M:%S]", &t);
}

// ─── Window Proc (WM_DEVICECHANGE) ───────────────────────────────────────────

LRESULT CALLBACK windowProc(HWND hwnd, UINT msg,
                            WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_DEVICECHANGE)
    {
        auto *hdr = reinterpret_cast<PDEV_BROADCAST_HDR>(lParam);

        // ── Device Plugged In ─────────────────────────────────────────────────
        if (wParam == DBT_DEVICEARRIVAL &&
            hdr && hdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
        {

            auto *iface = reinterpret_cast<PDEV_BROADCAST_DEVICEINTERFACE>(hdr);

            // Log the raw device path
            int size = WideCharToMultiByte(CP_UTF8, 0,
                                           iface->dbcc_name, -1,
                                           nullptr, 0, nullptr, nullptr);
            std::string devPath(size - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, iface->dbcc_name, -1,
                                &devPath[0], size, nullptr, nullptr);

            logEvent("[CONNECTED] " + devPath);

            // Small delay — let Windows finish enumerating the device
            Sleep(800);

            // ── Layer 1: Capture & Log Descriptor ────────────────────────────
            Layer1DescriptorAnalyzer::analyzeAll();
        }

        // ── Device Unplugged ──────────────────────────────────────────────────
        if (wParam == DBT_DEVICEREMOVECOMPLETE &&
            hdr && hdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
        {

            auto *iface = reinterpret_cast<PDEV_BROADCAST_DEVICEINTERFACE>(hdr);

            int size = WideCharToMultiByte(CP_UTF8, 0,
                                           iface->dbcc_name, -1,
                                           nullptr, 0, nullptr, nullptr);
            std::string devPath(size - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, iface->dbcc_name, -1,
                                &devPath[0], size, nullptr, nullptr);

            logEvent("[DISCONNECTED] " + devPath);
        }
    }

    if (msg == WM_DESTROY)
    {
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ─── Service Worker Thread ────────────────────────────────────────────────────

DWORD WINAPI serviceWorker(LPVOID)
{

    // Initialize logger and log directory
    DescriptorLogger::init(LOG_DIR);
    logEvent("[START] USB Descriptor Monitor service started.");

    // Register hidden message-only window
    WNDCLASSW wc{};
    wc.lpfnWndProc = windowProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"USBMonitorMsgWnd";

    if (!RegisterClassW(&wc))
    {
        logEvent("[ERROR] Failed to register window class: " +
                 std::to_string(GetLastError()));
        return 1;
    }

    g_MsgHwnd = CreateWindowExW(
        0, L"USBMonitorMsgWnd", L"",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,
        nullptr, GetModuleHandleW(nullptr), nullptr);

    if (!g_MsgHwnd)
    {
        logEvent("[ERROR] Failed to create message window: " +
                 std::to_string(GetLastError()));
        return 1;
    }

    // Register for USB device interface notifications
    DEV_BROADCAST_DEVICEINTERFACE filter{};
    filter.dbcc_size = sizeof(filter);
    filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    filter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;

    HDEVNOTIFY hNotify = RegisterDeviceNotificationW(
        g_MsgHwnd, &filter,
        DEVICE_NOTIFY_WINDOW_HANDLE);

    if (!hNotify)
    {
        logEvent("[ERROR] Failed to register device notification: " +
                 std::to_string(GetLastError()));
        return 1;
    }

    // Scan devices already connected at startup
    logEvent("[SCAN] Scanning already-connected USB devices...");
    Layer1DescriptorAnalyzer::analyzeAll();

    // ── Message Loop (runs until service stop signal) ─────────────────────────
    MSG msg{};
    while (WaitForSingleObject(g_StopEvent, 0) != WAIT_OBJECT_0)
    {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(100);
    }

    // Cleanup
    UnregisterDeviceNotification(hNotify);
    DestroyWindow(g_MsgHwnd);
    logEvent("[STOP] USB Descriptor Monitor service stopped.");

    return 0;
}

// ─── Service Control Handler ──────────────────────────────────────────────────

void WINAPI serviceCtrlHandler(DWORD ctrl)
{
    switch (ctrl)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_Status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_Status);
        SetEvent(g_StopEvent);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        // SCM asking for current status — just re-report it
        SetServiceStatus(g_StatusHandle, &g_Status);
        break;

    default:
        break;
    }
}

// ─── Service Main ─────────────────────────────────────────────────────────────

void WINAPI serviceMain(DWORD, LPWSTR *)
{

    // Register control handler
    g_StatusHandle = RegisterServiceCtrlHandlerW(
        SERVICE_NAME, serviceCtrlHandler);

    if (!g_StatusHandle)
        return;

    // Report: starting
    g_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwCurrentState = SERVICE_START_PENDING;
    g_Status.dwControlsAccepted = 0;
    SetServiceStatus(g_StatusHandle, &g_Status);

    // Create stop event
    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_StopEvent)
    {
        g_Status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_Status);
        return;
    }

    // Launch worker thread
    HANDLE worker = CreateThread(
        nullptr, 0, serviceWorker, nullptr, 0, nullptr);

    if (!worker)
    {
        g_Status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_Status);
        return;
    }

    // Report: running
    g_Status.dwCurrentState = SERVICE_RUNNING;
    g_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                  SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_StatusHandle, &g_Status);

    // Wait for stop signal
    WaitForSingleObject(g_StopEvent, INFINITE);
    WaitForSingleObject(worker, INFINITE);

    // Cleanup
    CloseHandle(worker);
    CloseHandle(g_StopEvent);

    // Report: stopped
    g_Status.dwCurrentState = SERVICE_STOPPED;
    g_Status.dwControlsAccepted = 0;
    SetServiceStatus(g_StatusHandle, &g_Status);
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

int wmain()
{
    SERVICE_TABLE_ENTRYW table[] = {
        {(LPWSTR)SERVICE_NAME, serviceMain},
        {nullptr, nullptr}};

    if (!StartServiceCtrlDispatcherW(table))
    {
        // If not running as a service, log the error
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            // Means it was run directly from console — useful for testing
            logEvent("[ERROR] Not running as a Windows Service. "
                     "Install via: sc create or the MSI installer.");
        }
    }

    return 0;
}