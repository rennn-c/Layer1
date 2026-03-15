// layer1_descriptor.h
// ─────────────────────────────────────────────────────────────────────────────
// LAYER 1: USB Descriptor Capture and Validation
// Captures USB device descriptors on plug-in, applies rule-based analysis,
// checks allow/block lists, and logs results to CSV and raw text files.
// This is the first layer of the multi-layer IDPS defined in the research paper.
// ─────────────────────────────────────────────────────────────────────────────
#pragma once

#include <windows.h>  // Core Windows API (HANDLE, DWORD, UINT, etc.)
#include <setupapi.h> // SetupDiGetClassDevs, SetupDiEnumDeviceInfo — enumerate devices
#include <usbiodef.h> // GUID_DEVINTERFACE_USB_DEVICE — USB device interface GUID
#include <cfgmgr32.h> // CM_Get_Device_IDW, CM_Get_Parent — device instance IDs
#include <string>     // std::string, std::wstring
#include <vector>     // std::vector — used for buffers and triggered rules list
#include <fstream>    // std::ifstream, std::ofstream — file read/write for logs
#include <sstream>    // std::ostringstream — build strings before writing to log
#include <iomanip>    // std::setw, std::setfill, std::hex — format hex VID/PID output
#include <ctime>      // time(), localtime_s(), strftime() — generate timestamps

#pragma comment(lib, "setupapi.lib") // Link SetupAPI library at compile time

// ─────────────────────────────────────────────────────────────────────────────
// STRUCT: USBDescriptorRecord
// Holds all captured data for a single USB device.
// One record is created per device per plug-in event.
// This is what gets written as one row in usb_descriptors.csv.
// ─────────────────────────────────────────────────────────────────────────────
struct USBDescriptorRecord
{
    // ── When it was detected ─────────────────────────────────────────────────
    std::string timestamp; // Date and time of detection e.g. "2026-03-15 19:01:00"

    // ── Device identity fields (from Windows registry via SetupAPI) ──────────
    std::string instanceId;   // Full device instance path e.g. "USB\VID_0781&PID_5577\..."
    std::string description;  // Windows device description e.g. "USB Mass Storage Device"
    std::string manufacturer; // iManufacturer string e.g. "SanDisk"
    std::string product;      // iProduct / friendly name e.g. "Cruzer Blade"
    std::string serialNumber; // iSerialNumber — last segment of instance ID
    std::string deviceClass;  // Windows device class e.g. "HIDClass", "USB", "MEDIA"
    std::string service;      // Driver service name e.g. "HidUsb", "USBSTOR", "usbccgp"
    std::string location;     // Physical port location e.g. "Port_#0012.Hub_#0001"
    UINT vendorId = 0;        // Vendor ID (VID) parsed from instance ID e.g. 0x0781
    UINT productId = 0;       // Product ID (PID) parsed from instance ID e.g. 0x5577

    // ── Interface-level class flags ──────────────────────────────────────────
    // These are derived by examining the device and its child interfaces.
    // A composite device can have multiple interface classes simultaneously.
    bool hasHID = false;         // Has a Human Interface Device interface (keyboard/mouse/injector)
    bool hasMassStorage = false; // Has a Mass Storage interface (flash drive behavior)
    bool hasCDC = false;         // Has a CDC/Serial interface (data channel — exfiltration risk)
    bool hasVendorClass = false; // Has a vendor-specific (0xFF) class (unknown/custom firmware)

    // ── Derived structural flags ─────────────────────────────────────────────
    bool isComposite = false;     // Device exposes multiple interface classes (higher risk)
    bool emptyVendorStr = false;  // iManufacturer string is blank or generic
    bool emptyProductStr = false; // iProduct string is blank or generic
    bool emptySerialStr = false;  // iSerialNumber is blank, too short, or missing

    // ── Layer 1 analysis result ──────────────────────────────────────────────
    std::string verdict; // Final verdict: "CLEAN" | "SUSPICIOUS" | "ALERT" | "BLOCKED"
    std::string reasons; // Pipe-separated list of triggered rules e.g. "R01:HID+MassStorage | R03:..."
};

// ─────────────────────────────────────────────────────────────────────────────
// CLASS: DeviceListManager
// Manages two persistent text files:
//   allowlist.txt — devices that are always trusted (skip all rules)
//   blocklist.txt — devices that are always blocked (previously flagged)
// Both files survive reboots and service restarts.
// Format of each file: one "VID:PID  # optional note" entry per line.
// ─────────────────────────────────────────────────────────────────────────────
class DeviceListManager
{
public:
    static std::wstring s_allowPath; // Full path to allowlist.txt
    static std::wstring s_blockPath; // Full path to blocklist.txt

    // Called once at startup — sets file paths and creates files if missing
    static void init(const std::wstring &logDir)
    {
        s_allowPath = logDir + L"\\allowlist.txt";
        s_blockPath = logDir + L"\\blocklist.txt";
        ensureFileExists(s_allowPath, "allowlist"); // Create allowlist.txt with header if not present
        ensureFileExists(s_blockPath, "blocklist"); // Create blocklist.txt with header if not present
    }

    // Returns true if this VID+PID exists in allowlist.txt
    static bool isAllowListed(UINT vid, UINT pid)
    {
        return isInFile(s_allowPath, vid, pid);
    }

    // Returns true if this VID+PID exists in blocklist.txt
    static bool isBlockListed(UINT vid, UINT pid)
    {
        return isInFile(s_blockPath, vid, pid);
    }

    // Adds a VID+PID entry to allowlist.txt (only if not already present)
    static void addToAllowList(UINT vid, UINT pid, const std::string &note = "")
    {
        if (!isAllowListed(vid, pid))
            appendToFile(s_allowPath, vid, pid, note);
    }

    // Adds a VID+PID entry to blocklist.txt (only if not already present)
    // Called automatically when a device triggers an ALERT verdict
    static void addToBlockList(UINT vid, UINT pid, const std::string &note = "")
    {
        if (!isBlockListed(vid, pid))
            appendToFile(s_blockPath, vid, pid, note);
    }

private:
    // Formats VID and PID as "XXXX:YYYY" uppercase hex string
    // Used as the lookup key in the list files
    static std::string vidPidKey(UINT vid, UINT pid)
    {
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0')
           << std::setw(4) << vid << ":"
           << std::setw(4) << pid;
        return ss.str();
    }

    // Reads a list file line by line, strips comments and whitespace,
    // and checks if the "VID:PID" key exists in any line
    static bool isInFile(const std::wstring &path, UINT vid, UINT pid)
    {
        std::ifstream f(path);
        if (!f)
            return false; // File doesn't exist or can't be opened

        std::string key = vidPidKey(vid, pid); // e.g. "0781:5577"
        std::string line;

        while (std::getline(f, line))
        {
            // Remove everything after '#' (comment)
            auto pos = line.find('#');
            if (pos != std::string::npos)
                line = line.substr(0, pos);

            // Trim leading whitespace
            line.erase(0, line.find_first_not_of(" \t\r\n"));

            // Trim trailing whitespace
            if (line.size() > line.find_last_not_of(" \t\r\n"))
                line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (line.empty())
                continue; // Skip blank/comment-only lines

            // Compare first 9 characters (format: "XXXX:YYYY")
            if (line.size() >= 9 && line.substr(0, 9) == key)
                return true;
        }
        return false;
    }

    // Appends a new "VID:PID  # note" line to a list file
    static void appendToFile(const std::wstring &path,
                             UINT vid, UINT pid,
                             const std::string &note)
    {
        std::ofstream f(path, std::ios::app); // Open in append mode
        if (!f)
            return;
        f << vidPidKey(vid, pid);
        if (!note.empty())
            f << "  # " << note; // Add note as comment
        f << "\n";
    }

    // Creates a list file with a header comment block if it doesn't exist yet
    static void ensureFileExists(const std::wstring &path,
                                 const std::string &listName)
    {
        std::ifstream check(path);
        if (!check.good()) // File does not exist
        {
            std::ofstream f(path);
            f << "# USB Monitor - " << listName << "\n";
            f << "# Format: VID:PID  # optional note\n";
            f << "# Example: 046D:C52B  # Logitech USB Receiver\n\n";
        }
    }
};

// Static member definitions — required for linker
std::wstring DeviceListManager::s_allowPath;
std::wstring DeviceListManager::s_blockPath;

// ─────────────────────────────────────────────────────────────────────────────
// CLASS: DescriptorLogger
// Handles all file output for Layer 1:
//   usb_descriptors.csv — structured dataset (one row per device per event)
//   usb_raw.txt         — human-readable full descriptor dump
// ─────────────────────────────────────────────────────────────────────────────
class DescriptorLogger
{
public:
    // Called once at startup — creates log directory, initializes list manager,
    // and writes the CSV header row if the file doesn't exist yet
    static void init(const std::wstring &logDir)
    {
        CreateDirectoryW(logDir.c_str(), nullptr); // Create C:\ProgramData\USBMonitor\ if missing

        s_logPath = logDir + L"\\usb_descriptors.csv"; // Path to structured CSV dataset
        s_rawPath = logDir + L"\\usb_raw.txt";         // Path to human-readable log

        DeviceListManager::init(logDir); // Initialize allow/block list files

        // Write CSV header only if the file is being created fresh
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

    // Appends one device record as a CSV row to usb_descriptors.csv
    static void writeCSV(const USBDescriptorRecord &r)
    {
        std::ofstream f(s_logPath, std::ios::app); // Append mode — never overwrites
        f << csvField(r.timestamp) << ","
          << csvField(r.instanceId) << ","
          << std::hex << "0x" << std::setw(4) << std::setfill('0') << r.vendorId << ","
          << std::hex << "0x" << std::setw(4) << std::setfill('0') << r.productId << ","
          << std::dec // Switch back to decimal for boolean columns
          << csvField(r.description) << ","
          << csvField(r.manufacturer) << ","
          << csvField(r.product) << ","
          << csvField(r.serialNumber) << ","
          << csvField(r.deviceClass) << ","
          << csvField(r.service) << ","
          << csvField(r.location) << ","
          << r.hasHID << ","          // 1 or 0
          << r.hasMassStorage << ","  // 1 or 0
          << r.hasCDC << ","          // 1 or 0
          << r.hasVendorClass << ","  // 1 or 0
          << r.isComposite << ","     // 1 or 0
          << r.emptyVendorStr << ","  // 1 or 0
          << r.emptyProductStr << "," // 1 or 0
          << r.emptySerialStr << ","  // 1 or 0
          << csvField(r.verdict) << ","
          << csvField(r.reasons) << "\n";
    }

    // Appends a raw text block to usb_raw.txt
    static void writeRaw(const std::string &text)
    {
        std::ofstream f(s_rawPath, std::ios::app); // Append mode
        f << text << "\n";
    }

private:
    static std::wstring s_logPath; // Path to usb_descriptors.csv
    static std::wstring s_rawPath; // Path to usb_raw.txt

    // Wraps a string value in CSV-safe double quotes,
    // and escapes any inner double quotes by doubling them
    static std::string csvField(const std::string &s)
    {
        std::string out = "\"";
        for (char c : s)
        {
            if (c == '"')
                out += "\"\""; // Escape inner quote
            else
                out += c;
        }
        out += "\"";
        return out;
    }
};

// Static member definitions
std::wstring DescriptorLogger::s_logPath;
std::wstring DescriptorLogger::s_rawPath;

// ─────────────────────────────────────────────────────────────────────────────
// CLASS: Layer1DescriptorAnalyzer
// Core Layer 1 logic. Called every time a USB device is plugged in.
// Pipeline: enumerate → build record → check lists → apply rules → log
// ─────────────────────────────────────────────────────────────────────────────
class Layer1DescriptorAnalyzer
{
public:
    // Entry point — enumerates all currently connected USB devices,
    // builds a descriptor record for each, and runs the analysis pipeline
    static void analyzeAll()
    {
        // Get a list of all present devices across all classes filtered by "USB" enumerator
        HDEVINFO devInfo = SetupDiGetClassDevsW(
            nullptr, L"USB", nullptr,
            DIGCF_PRESENT | DIGCF_ALLCLASSES);

        if (devInfo == INVALID_HANDLE_VALUE)
            return; // Failed to get device list

        SP_DEVINFO_DATA devData{};
        devData.cbSize = sizeof(SP_DEVINFO_DATA); // Required size field for SetupAPI

        // Iterate through every device in the list
        for (DWORD i = 0; SetupDiEnumDeviceInfo(devInfo, i, &devData); i++)
        {
            // Get the full device instance ID string e.g. "USB\VID_0781&PID_5577\..."
            WCHAR idW[MAX_DEVICE_ID_LEN]{};
            CM_Get_Device_IDW(devData.DevInst, idW, MAX_DEVICE_ID_LEN, 0);
            std::string instanceId = wstrToStr(idW);

            // Skip non-USB devices and hub/root entries without VID/PID
            if (instanceId.find("USB\\VID_") == std::string::npos)
                continue;

            // Run the full analysis pipeline for this device
            USBDescriptorRecord rec = buildRecord(devInfo, devData, instanceId);
            applyRules(rec); // Check lists and apply descriptor rules
            logRecord(rec);  // Write to CSV and raw log
        }

        SetupDiDestroyDeviceInfoList(devInfo); // Free the device info list
    }

private:
    // ── Step 1: Build Record ─────────────────────────────────────────────────
    // Reads all available descriptor fields from the Windows registry
    // via SetupAPI and populates a USBDescriptorRecord struct
    static USBDescriptorRecord buildRecord(HDEVINFO devInfo,
                                           SP_DEVINFO_DATA &devData,
                                           const std::string &instanceId)
    {
        USBDescriptorRecord r;

        r.timestamp = getTimestamp(); // Current date/time
        r.instanceId = instanceId;    // Full instance path

        // Read registry properties via SetupAPI
        r.description = getProperty(devInfo, devData, SPDRP_DEVICEDESC);        // Device description
        r.manufacturer = getProperty(devInfo, devData, SPDRP_MFG);              // Manufacturer string
        r.product = getProperty(devInfo, devData, SPDRP_FRIENDLYNAME);          // Friendly/product name
        r.deviceClass = getProperty(devInfo, devData, SPDRP_CLASS);             // Device class name
        r.service = getProperty(devInfo, devData, SPDRP_SERVICE);               // Driver service name
        r.location = getProperty(devInfo, devData, SPDRP_LOCATION_INFORMATION); // Port location

        // Serial number is the last segment of the instance ID path
        auto lastSlash = instanceId.rfind('\\');
        r.serialNumber = (lastSlash != std::string::npos)
                             ? instanceId.substr(lastSlash + 1)
                             : "(none)";

        parseVidPid(instanceId, r.vendorId, r.productId); // Extract VID and PID from instance ID

        detectInterfaceClasses(devInfo, devData, r); // Detect what interfaces this device exposes

        // Flag blank or generic strings that indicate missing/spoofed descriptor fields
        r.emptyVendorStr = (r.manufacturer.empty() || r.manufacturer == "(none)");
        r.emptyProductStr = (r.product.empty() || r.product == "(none)");
        r.emptySerialStr = (r.serialNumber.empty() || r.serialNumber == "(none)" || r.serialNumber.size() < 4); // Very short serial = suspicious

        return r;
    }

    // ── Step 2: Detect Interface Classes ─────────────────────────────────────
    // For simple devices, reads class from the device itself.
    // For composite devices (service = usbccgp), enumerates child interfaces
    // to find all interface classes hidden inside the composite device.
    static void detectInterfaceClasses(HDEVINFO devInfo,
                                       SP_DEVINFO_DATA &devData,
                                       USBDescriptorRecord &r)
    {
        // Check the top-level device class first
        classifyString(r.service, r.deviceClass, r.description, r);

        // usbccgp = USB Common Class Generic Parent Driver = composite device
        if (r.service.find("usbccgp") != std::string::npos ||
            r.service.find("USBCCGP") != std::string::npos)
        {
            r.isComposite = true; // Mark as composite immediately

            // Enumerate ALL present devices to find children of this device
            HDEVINFO childInfo = SetupDiGetClassDevsW(
                nullptr, nullptr, nullptr,
                DIGCF_PRESENT | DIGCF_ALLCLASSES);

            if (childInfo == INVALID_HANDLE_VALUE)
                return;

            // Get this device's instance ID to match against children's parent
            WCHAR parentId[MAX_DEVICE_ID_LEN]{};
            CM_Get_Device_IDW(devData.DevInst, parentId, MAX_DEVICE_ID_LEN, 0);
            std::string parentIdStr = wstrToStr(parentId);

            SP_DEVINFO_DATA childData{};
            childData.cbSize = sizeof(SP_DEVINFO_DATA);

            for (DWORD j = 0; SetupDiEnumDeviceInfo(childInfo, j, &childData); j++)
            {
                // Get this candidate's parent device instance
                DEVINST parent;
                if (CM_Get_Parent(&parent, childData.DevInst, 0) != CR_SUCCESS)
                    continue;

                // Get the parent's instance ID and compare to our device
                WCHAR pid[MAX_DEVICE_ID_LEN]{};
                CM_Get_Device_IDW(parent, pid, MAX_DEVICE_ID_LEN, 0);
                if (wstrToStr(pid) != parentIdStr)
                    continue; // Not our child

                // This is a child interface — read its class and service
                std::string childSvc = getProperty(childInfo, childData, SPDRP_SERVICE);
                std::string childCls = getProperty(childInfo, childData, SPDRP_CLASS);
                std::string childDsc = getProperty(childInfo, childData, SPDRP_DEVICEDESC);

                classifyString(childSvc, childCls, childDsc, r); // Classify this child interface
            }

            SetupDiDestroyDeviceInfoList(childInfo);
        }

        // If multiple distinct interface types found, mark composite regardless of driver
        int ifaceCount = (int)r.hasHID + (int)r.hasMassStorage + (int)r.hasCDC + (int)r.hasVendorClass;
        if (ifaceCount > 1)
            r.isComposite = true;
    }

    // Classifies a device/interface into known categories based on
    // its service name, class name, and device description string
    static void classifyString(const std::string &svc,
                               const std::string &cls,
                               const std::string &descr,
                               USBDescriptorRecord &r)
    {
        auto contains = [](const std::string &s, const std::string &sub)
        {
            return s.find(sub) != std::string::npos;
        };

        // HID: Human Interface Device — keyboards, mice, gamepads, and HID injectors
        if (contains(cls, "HID") || contains(svc, "HidUsb") ||
            contains(descr, "HID") || contains(descr, "Keyboard") ||
            contains(descr, "Mouse"))
            r.hasHID = true;

        // Mass Storage: flash drives, external HDDs
        if (contains(cls, "DiskDrive") || contains(cls, "USBSTOR") ||
            contains(svc, "USBSTOR") || contains(svc, "disk") ||
            contains(descr, "Storage") || contains(descr, "Flash") ||
            contains(descr, "Drive"))
            r.hasMassStorage = true;

        // CDC/Serial: USB-to-serial adapters, modems — potential data exfiltration channel
        if (contains(cls, "Modem") || contains(svc, "usbser") ||
            contains(descr, "Serial") || contains(descr, "CDC"))
            r.hasCDC = true;

        // Vendor-specific: WinUSB or libusb = custom/unknown firmware behavior
        if (contains(svc, "WinUSB") || contains(svc, "libusb") ||
            contains(cls, "Unknown") || cls == "(none)")
            r.hasVendorClass = true;
    }

    // ── Step 3: Apply Rules ───────────────────────────────────────────────────
    // Implements the plug-in decision flow from the research design:
    //   1. Check allow-list  → CLEAN if found
    //   2. Check block-list  → BLOCKED if found
    //   3. Apply descriptor rules R01-R07
    //   4. Auto-block if ALERT verdict reached
    static void applyRules(USBDescriptorRecord &r)
    {
        std::vector<std::string> triggered; // Collects all triggered rule IDs

        // ── Step 1: Allow-list ────────────────────────────────────────────────
        // If device is in allowlist.txt, skip all further checks
        if (DeviceListManager::isAllowListed(r.vendorId, r.productId))
        {
            r.verdict = "CLEAN";
            r.reasons = "allow-listed device";
            return; // Stop here — trusted device
        }

        // ── Step 2: Remember-Blocked ──────────────────────────────────────────
        // If device was previously flagged and saved to blocklist.txt, block immediately
        if (DeviceListManager::isBlockListed(r.vendorId, r.productId))
        {
            r.verdict = "BLOCKED";
            r.reasons = "remember-blocked device";
            return; // Stop here — previously flagged device
        }

        // ── Step 3: Descriptor Rules ──────────────────────────────────────────
        // (CAPTCHA check will be inserted here in Layer 3)

        // R01: HID + Mass Storage — classic BadUSB / Rubber Ducky signature
        // Device pretends to be a keyboard AND a storage device simultaneously
        if (r.hasHID && r.hasMassStorage)
        {
            triggered.push_back("R01:HID+MassStorage(BadUSB pattern)");
            r.verdict = "ALERT";
        }

        // R02: HID + CDC — keyboard injector that also opens a serial data channel
        // Can inject commands AND exfiltrate data at the same time
        if (r.hasHID && r.hasCDC)
        {
            triggered.push_back("R02:HID+CDC(injection+exfiltration risk)");
            r.verdict = "ALERT";
        }

        // R03: HID device with no manufacturer string
        // Legitimate keyboards always have a manufacturer name
        if (r.hasHID && r.emptyVendorStr)
        {
            triggered.push_back("R03:HID with no manufacturer string");
            if (r.verdict != "ALERT")
                r.verdict = "SUSPICIOUS";
        }

        // R04: HID device with no serial number
        // Rubber Ducky and similar tools often lack a proper serial number
        if (r.hasHID && r.emptySerialStr)
        {
            triggered.push_back("R04:HID with no serial number");
            if (r.verdict != "ALERT")
                r.verdict = "SUSPICIOUS";
        }

        // R05: Composite device that contains a HID interface
        // Normal keyboards can be composite — this is a soft flag for review
        // False positives are handled by adding the device to allowlist.txt
        if (r.isComposite && r.hasHID)
        {
            triggered.push_back("R05:Composite device contains HID interface");
            if (r.verdict != "ALERT")
                r.verdict = "SUSPICIOUS";
        }

        // R06: Vendor-specific (0xFF) class device that is not storage
        // Fully custom firmware with unknown behavior — higher risk
        if (r.hasVendorClass && !r.hasMassStorage)
        {
            triggered.push_back("R06:Vendor-specific class(unrecognized firmware)");
            if (r.verdict.empty())
                r.verdict = "SUSPICIOUS";
        }

        // R07: All three descriptor strings are blank or missing
        // Legitimate devices always have at least one string descriptor
        // All blank = possibly spoofed or stripped descriptor (firmware manipulation)
        if (r.emptyVendorStr && r.emptyProductStr && r.emptySerialStr)
        {
            triggered.push_back("R07:All descriptor strings empty(possible spoofing)");
            if (r.verdict != "ALERT")
                r.verdict = "SUSPICIOUS";
        }

        // No rules triggered — device passes Layer 1
        if (r.verdict.empty())
            r.verdict = "CLEAN";

        // Build the pipe-separated reasons string
        for (size_t i = 0; i < triggered.size(); i++)
        {
            if (i > 0)
                r.reasons += " | ";
            r.reasons += triggered[i];
        }
        if (r.reasons.empty())
            r.reasons = "none";

        // ── Step 4: Auto-remember-block on ALERT ─────────────────────────────
        // Devices that trigger R01 or R02 are automatically saved to blocklist.txt
        // so they are blocked immediately on every future plug-in
        if (r.verdict == "ALERT")
        {
            DeviceListManager::addToBlockList(
                r.vendorId, r.productId,
                "auto-blocked: " + r.reasons);
        }
    }

    // ── Step 4: Log Record ────────────────────────────────────────────────────
    // Writes the completed record to both output files
    static void logRecord(const USBDescriptorRecord &r)
    {
        // Build human-readable block for usb_raw.txt
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
        raw << "    Verdict:  " << r.verdict << "\n"; // Final decision
        raw << "    Reasons:  " << r.reasons << "\n"; // What triggered it

        DescriptorLogger::writeRaw(raw.str()); // Write to usb_raw.txt
        DescriptorLogger::writeCSV(r);         // Write to usb_descriptors.csv
    }

    // ── Utility Functions ─────────────────────────────────────────────────────

    // Reads a single string registry property from a device info entry
    // Returns "(none)" if the property is missing or empty
    static std::string getProperty(HDEVINFO di, SP_DEVINFO_DATA &dd, DWORD prop)
    {
        DWORD size = 0;
        // First call with null buffer to get required buffer size
        SetupDiGetDeviceRegistryPropertyW(di, &dd, prop, nullptr, nullptr, 0, &size);
        if (!size)
            return "(none)";

        std::vector<BYTE> buf(size); // Allocate exact buffer size
        if (!SetupDiGetDeviceRegistryPropertyW(di, &dd, prop, nullptr,
                                               buf.data(), size, nullptr))
            return "(error)";

        return wstrToStr(reinterpret_cast<wchar_t *>(buf.data())); // Convert wide to UTF-8
    }

    // Parses VID and PID from a device instance ID string
    // e.g. "USB\VID_0781&PID_5577\..." → vid=0x0781, pid=0x5577
    static bool parseVidPid(const std::string &id, UINT &vid, UINT &pid)
    {
        auto vp = id.find("VID_"), pp = id.find("PID_");
        if (vp == std::string::npos || pp == std::string::npos)
            return false;
        try
        {
            vid = std::stoul(id.substr(vp + 4, 4), nullptr, 16); // 4 hex chars after "VID_"
            pid = std::stoul(id.substr(pp + 4, 4), nullptr, 16); // 4 hex chars after "PID_"
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    // Converts a wide string (wchar_t) to a UTF-8 narrow string (char)
    // Required because Windows registry returns wide strings
    static std::string wstrToStr(const std::wstring &w)
    {
        if (w.empty())
            return {};
        // Get required buffer size first
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                                    nullptr, 0, nullptr, nullptr);
        std::string s(n - 1, 0); // Allocate buffer (n-1 to exclude null terminator)
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                            &s[0], n, nullptr, nullptr); // Do the conversion
        return s;
    }

    // Returns current local time as a formatted string "YYYY-MM-DD HH:MM:SS"
    static std::string getTimestamp()
    {
        time_t now = time(nullptr); // Get current time as epoch
        struct tm t;
        localtime_s(&t, &now); // Convert to local time (thread-safe version)
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &t); // Format as string
        return buf;
    }
};