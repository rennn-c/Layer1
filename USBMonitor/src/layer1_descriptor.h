// layer1_descriptor.h
#pragma once

#include <windows.h>
#include <setupapi.h>
#include <usbiodef.h>
#include <cfgmgr32.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>

#pragma comment(lib, "setupapi.lib")

// ─── Descriptor Record (one per device) ─────────────────────────────────────
// This struct is what gets written to the dataset CSV

struct USBDescriptorRecord
{
    // Timing
    std::string timestamp;

    // Device Descriptor
    std::string instanceId;
    std::string description;
    std::string manufacturer;
    std::string product;
    std::string serialNumber;
    std::string deviceClass; // from registry (human readable)
    std::string service;     // driver service name
    std::string location;
    UINT vendorId = 0;
    UINT productId = 0;

    // Interface-level class info (parsed from instance ID / registry)
    bool hasHID = false;
    bool hasMassStorage = false;
    bool hasCDC = false;         // USB communications (modem-like)
    bool hasVendorClass = false; // 0xFF = fully custom / suspicious

    // Derived flags for Layer 1 analysis
    bool isComposite = false;     // multiple interface classes
    bool emptyVendorStr = false;  // iManufacturer blank
    bool emptyProductStr = false; // iProduct blank
    bool emptySerialStr = false;  // iSerialNumber blank

    // Layer 1 verdict
    std::string verdict; // "CLEAN" | "SUSPICIOUS" | "ALERT"
    std::string reasons; // pipe-separated list of triggered rules
};

// ─── Logger ──────────────────────────────────────────────────────────────────

class DescriptorLogger
{
public:
    static void init(const std::wstring &logDir)
    {
        CreateDirectoryW(logDir.c_str(), nullptr);
        s_logPath = logDir + L"\\usb_descriptors.csv";
        s_rawPath = logDir + L"\\usb_raw.txt";

        // Write CSV header if file is new
        std::ifstream check(s_logPath);
        if (!check.good())
        {
            std::ofstream f(s_logPath);
            f << "timestamp,instance_id,vendor_id,product_id,"
                 "description,manufacturer,product,serial_number,"
                 "device_class,service,location,"
                 "has_hid,has_mass_storage,has_cdc,has_vendor_class,"
                 "is_composite,empty_vendor,empty_product,empty_serial,"
                 "verdict,reasons\n";
        }
    }

    static void writeCSV(const USBDescriptorRecord &r)
    {
        std::ofstream f(s_logPath, std::ios::app);
        f << csvField(r.timestamp) << ","
          << csvField(r.instanceId) << ","
          << std::hex << "0x" << std::setw(4) << std::setfill('0') << r.vendorId << ","
          << std::hex << "0x" << std::setw(4) << std::setfill('0') << r.productId << ","
          << std::dec
          << csvField(r.description) << ","
          << csvField(r.manufacturer) << ","
          << csvField(r.product) << ","
          << csvField(r.serialNumber) << ","
          << csvField(r.deviceClass) << ","
          << csvField(r.service) << ","
          << csvField(r.location) << ","
          << r.hasHID << ","
          << r.hasMassStorage << ","
          << r.hasCDC << ","
          << r.hasVendorClass << ","
          << r.isComposite << ","
          << r.emptyVendorStr << ","
          << r.emptyProductStr << ","
          << r.emptySerialStr << ","
          << csvField(r.verdict) << ","
          << csvField(r.reasons) << "\n";
    }

    static void writeRaw(const std::string &text)
    {
        std::ofstream f(s_rawPath, std::ios::app);
        f << text << "\n";
    }

private:
    static std::wstring s_logPath;
    static std::wstring s_rawPath;

    static std::string csvField(const std::string &s)
    {
        // Wrap in quotes and escape inner quotes
        std::string out = "\"";
        for (char c : s)
        {
            if (c == '"')
                out += "\"\"";
            else
                out += c;
        }
        out += "\"";
        return out;
    }
};

std::wstring DescriptorLogger::s_logPath;
std::wstring DescriptorLogger::s_rawPath;

// ─── Layer 1: Descriptor Analyzer ────────────────────────────────────────────

class Layer1DescriptorAnalyzer
{
public:
    // Called on every USB plug-in event
    static void analyzeAll()
    {
        HDEVINFO devInfo = SetupDiGetClassDevsW(
            nullptr, L"USB", nullptr,
            DIGCF_PRESENT | DIGCF_ALLCLASSES);

        if (devInfo == INVALID_HANDLE_VALUE)
            return;

        SP_DEVINFO_DATA devData{};
        devData.cbSize = sizeof(SP_DEVINFO_DATA);

        for (DWORD i = 0; SetupDiEnumDeviceInfo(devInfo, i, &devData); i++)
        {
            WCHAR idW[MAX_DEVICE_ID_LEN]{};
            CM_Get_Device_IDW(devData.DevInst, idW, MAX_DEVICE_ID_LEN, 0);
            std::string instanceId = wstrToStr(idW);

            // Only USB devices with VID/PID
            if (instanceId.find("USB\\VID_") == std::string::npos)
                continue;

            USBDescriptorRecord rec = buildRecord(devInfo, devData, instanceId);
            applyRules(rec);
            logRecord(rec);
        }

        SetupDiDestroyDeviceInfoList(devInfo);
    }

private:
    // ── Build the record from SetupAPI ───────────────────────────────────────

    static USBDescriptorRecord buildRecord(HDEVINFO devInfo,
                                           SP_DEVINFO_DATA &devData,
                                           const std::string &instanceId)
    {
        USBDescriptorRecord r;
        r.timestamp = getTimestamp();
        r.instanceId = instanceId;
        r.description = getProperty(devInfo, devData, SPDRP_DEVICEDESC);
        r.manufacturer = getProperty(devInfo, devData, SPDRP_MFG);
        r.product = getProperty(devInfo, devData, SPDRP_FRIENDLYNAME);
        r.deviceClass = getProperty(devInfo, devData, SPDRP_CLASS);
        r.service = getProperty(devInfo, devData, SPDRP_SERVICE);
        r.location = getProperty(devInfo, devData, SPDRP_LOCATION_INFORMATION);

        // Serial number lives in the instance ID  (last segment)
        auto lastSlash = instanceId.rfind('\\');
        r.serialNumber = (lastSlash != std::string::npos)
                             ? instanceId.substr(lastSlash + 1)
                             : "(none)";

        parseVidPid(instanceId, r.vendorId, r.productId);
        detectInterfaceClasses(devInfo, devData, r);

        // Blank string checks
        r.emptyVendorStr = (r.manufacturer.empty() || r.manufacturer == "(none)");
        r.emptyProductStr = (r.product.empty() || r.product == "(none)");
        r.emptySerialStr = (r.serialNumber.empty() || r.serialNumber == "(none)" || r.serialNumber.size() < 4); // very short = suspicious

        return r;
    }

    // ── Detect interface-level classes ────────────────────────────────────────
    // Composite devices (service = usbccgp) expose child devices.
    // We enumerate children to find what classes are actually inside.

    static void detectInterfaceClasses(HDEVINFO devInfo,
                                       SP_DEVINFO_DATA &devData,
                                       USBDescriptorRecord &r)
    {

        std::string svc = r.service;
        std::string cls = r.deviceClass;
        std::string descr = r.description;

        // Direct class from device itself
        classifyString(svc, cls, descr, r);

        // Composite device — enumerate child interfaces
        if (svc.find("usbccgp") != std::string::npos ||
            svc.find("USBCCGP") != std::string::npos)
        {
            r.isComposite = true;

            // Find children via SetupAPI
            HDEVINFO childInfo = SetupDiGetClassDevsW(
                nullptr, nullptr, nullptr,
                DIGCF_PRESENT | DIGCF_ALLCLASSES);

            if (childInfo == INVALID_HANDLE_VALUE)
                return;

            SP_DEVINFO_DATA childData{};
            childData.cbSize = sizeof(SP_DEVINFO_DATA);

            WCHAR parentId[MAX_DEVICE_ID_LEN]{};
            CM_Get_Device_IDW(devData.DevInst, parentId, MAX_DEVICE_ID_LEN, 0);
            std::string parentIdStr = wstrToStr(parentId);

            for (DWORD j = 0; SetupDiEnumDeviceInfo(childInfo, j, &childData); j++)
            {
                DEVINST parent;
                if (CM_Get_Parent(&parent, childData.DevInst, 0) != CR_SUCCESS)
                    continue;

                WCHAR pid[MAX_DEVICE_ID_LEN]{};
                CM_Get_Device_IDW(parent, pid, MAX_DEVICE_ID_LEN, 0);
                if (wstrToStr(pid) != parentIdStr)
                    continue;

                std::string childSvc = getProperty(childInfo, childData, SPDRP_SERVICE);
                std::string childCls = getProperty(childInfo, childData, SPDRP_CLASS);
                std::string childDsc = getProperty(childInfo, childData, SPDRP_DEVICEDESC);

                classifyString(childSvc, childCls, childDsc, r);
            }

            SetupDiDestroyDeviceInfoList(childInfo);
        }

        // Count distinct interface types
        int ifaceCount = (int)r.hasHID + (int)r.hasMassStorage + (int)r.hasCDC + (int)r.hasVendorClass;
        if (ifaceCount > 1)
            r.isComposite = true;
    }

    static void classifyString(const std::string &svc,
                               const std::string &cls,
                               const std::string &descr,
                               USBDescriptorRecord &r)
    {
        auto contains = [](const std::string &s, const std::string &sub)
        {
            return s.find(sub) != std::string::npos;
        };

        // HID
        if (contains(cls, "HID") || contains(svc, "HidUsb") ||
            contains(descr, "HID") || contains(descr, "Keyboard") ||
            contains(descr, "Mouse"))
            r.hasHID = true;

        // Mass Storage
        if (contains(cls, "DiskDrive") || contains(cls, "USBSTOR") ||
            contains(svc, "USBSTOR") || contains(svc, "disk") ||
            contains(descr, "Storage") || contains(descr, "Flash") ||
            contains(descr, "Drive"))
            r.hasMassStorage = true;

        // CDC (communications — can be used for exfiltration)
        if (contains(cls, "Modem") || contains(svc, "usbser") ||
            contains(descr, "Serial") || contains(descr, "CDC"))
            r.hasCDC = true;

        // Vendor-specific (0xFF) — fully custom firmware
        if (contains(svc, "WinUSB") || contains(svc, "libusb") ||
            contains(cls, "Unknown") || cls == "(none)")
            r.hasVendorClass = true;
    }

    // ── Layer 1 Rules ─────────────────────────────────────────────────────────

    static void applyRules(USBDescriptorRecord &r)
    {
        std::vector<std::string> triggered;

        // Rule 1: HID + Mass Storage = classic BadUSB / Rubber Ducky pattern
        if (r.hasHID && r.hasMassStorage)
        {
            triggered.push_back("R01:HID+MassStorage(BadUSB pattern)");
            r.verdict = "ALERT";
        }

        // Rule 2: HID + CDC = potential exfiltration via serial while injecting
        if (r.hasHID && r.hasCDC)
        {
            triggered.push_back("R02:HID+CDC(injection+exfiltration risk)");
            r.verdict = "ALERT";
        }

        // Rule 3: HID device with no manufacturer string
        if (r.hasHID && r.emptyVendorStr)
        {
            triggered.push_back("R03:HID with no manufacturer string");
            if (r.verdict != "ALERT")
                r.verdict = "SUSPICIOUS";
        }

        // Rule 4: HID device with no serial number
        if (r.hasHID && r.emptySerialStr)
        {
            triggered.push_back("R04:HID with no serial number");
            if (r.verdict != "ALERT")
                r.verdict = "SUSPICIOUS";
        }

        // Rule 5: Composite device with HID
        if (r.isComposite && r.hasHID)
        {
            triggered.push_back("R05:Composite device contains HID interface");
            if (r.verdict != "ALERT")
                r.verdict = "SUSPICIOUS";
        }

        // Rule 6: Vendor-specific class (unknown firmware behavior)
        if (r.hasVendorClass && !r.hasMassStorage)
        {
            triggered.push_back("R06:Vendor-specific class (unrecognized firmware)");
            if (r.verdict.empty())
                r.verdict = "SUSPICIOUS";
        }

        // Rule 7: All strings empty (spoofed / stripped descriptor)
        if (r.emptyVendorStr && r.emptyProductStr && r.emptySerialStr)
        {
            triggered.push_back("R07:All descriptor strings empty (possible spoofing)");
            if (r.verdict != "ALERT")
                r.verdict = "SUSPICIOUS";
        }

        // Clean if no rules triggered
        if (r.verdict.empty())
            r.verdict = "CLEAN";

        // Join reasons
        for (size_t i = 0; i < triggered.size(); i++)
        {
            if (i > 0)
                r.reasons += " | ";
            r.reasons += triggered[i];
        }
        if (r.reasons.empty())
            r.reasons = "none";
    }

    // ── Output ────────────────────────────────────────────────────────────────

    static void logRecord(const USBDescriptorRecord &r)
    {
        // Human-readable raw log
        std::ostringstream raw;
        raw << "==============================\n";
        raw << "  Timestamp:    " << r.timestamp << "\n";
        raw << "  Description:  " << r.description << "\n";
        raw << "  Manufacturer: " << r.manufacturer << "\n";
        raw << "  Product:      " << r.product << "\n";
        raw << "  Serial:       " << r.serialNumber << "\n";
        raw << "  Class:        " << r.deviceClass << "\n";
        raw << "  Service:      " << r.service << "\n";
        raw << "  Location:     " << r.location << "\n";
        raw << std::hex << std::uppercase << std::setfill('0');
        raw << "  VendorID:     0x" << std::setw(4) << r.vendorId << "\n";
        raw << "  ProductID:    0x" << std::setw(4) << r.productId << "\n";
        raw << std::dec;
        raw << "  [Interfaces]\n";
        raw << "    HID:          " << (r.hasHID ? "YES" : "no") << "\n";
        raw << "    MassStorage:  " << (r.hasMassStorage ? "YES" : "no") << "\n";
        raw << "    CDC/Serial:   " << (r.hasCDC ? "YES" : "no") << "\n";
        raw << "    VendorClass:  " << (r.hasVendorClass ? "YES" : "no") << "\n";
        raw << "    Composite:    " << (r.isComposite ? "YES" : "no") << "\n";
        raw << "  [String Checks]\n";
        raw << "    EmptyVendor:  " << (r.emptyVendorStr ? "YES" : "no") << "\n";
        raw << "    EmptyProduct: " << (r.emptyProductStr ? "YES" : "no") << "\n";
        raw << "    EmptySerial:  " << (r.emptySerialStr ? "YES" : "no") << "\n";
        raw << "  [Layer 1 Verdict]\n";
        raw << "    Verdict:  " << r.verdict << "\n";
        raw << "    Reasons:  " << r.reasons << "\n";

        DescriptorLogger::writeRaw(raw.str());
        DescriptorLogger::writeCSV(r);
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    static std::string getProperty(HDEVINFO di, SP_DEVINFO_DATA &dd, DWORD prop)
    {
        DWORD size = 0;
        SetupDiGetDeviceRegistryPropertyW(di, &dd, prop, nullptr, nullptr, 0, &size);
        if (!size)
            return "(none)";
        std::vector<BYTE> buf(size);
        if (!SetupDiGetDeviceRegistryPropertyW(di, &dd, prop, nullptr,
                                               buf.data(), size, nullptr))
            return "(error)";
        return wstrToStr(reinterpret_cast<wchar_t *>(buf.data()));
    }

    static bool parseVidPid(const std::string &id, UINT &vid, UINT &pid)
    {
        auto vp = id.find("VID_"), pp = id.find("PID_");
        if (vp == std::string::npos || pp == std::string::npos)
            return false;
        try
        {
            vid = std::stoul(id.substr(vp + 4, 4), nullptr, 16);
            pid = std::stoul(id.substr(pp + 4, 4), nullptr, 16);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    static std::string wstrToStr(const std::wstring &w)
    {
        if (w.empty())
            return {};
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                                    nullptr, 0, nullptr, nullptr);
        std::string s(n - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                            &s[0], n, nullptr, nullptr);
        return s;
    }

    static std::string getTimestamp()
    {
        time_t now = time(nullptr);
        struct tm t;
        localtime_s(&t, &now);
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &t);
        return buf;
    }
};