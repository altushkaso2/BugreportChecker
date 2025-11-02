#include "rules/Rules.h"

namespace Core {
    namespace Rules {

        std::vector<std::string> SystemPropertyRule::getTargetSections() const { return {"SYSTEM PROPERTIES"}; }
        DetectionCategory SystemPropertyRule::getTargetCategory() const { return DetectionCategory::RootAndFrameworks; }
        
        void SystemPropertyRule::processLine(std::string_view line, ReportData& report, AnalysisContext& context) {
            std::string_view key, value;
            parse_property_line(line, key, value);
            if (key.empty()) return;
            if (key == "ro.product.model") report.model = std::string(value);
            else if (key == "ro.product.brand") report.brand = std::string(value);
            else if (key == "ro.product.device") report.device = std::string(value);
            else if (key == "ro.build.version.release") report.androidVersion = std::string(value);
            else if (key == "ro.build.fingerprint") report.buildFingerprint = std::string(value);
            else if (key == "ro.serialno") report.serialNumber = std::string(value);
            else if (key == "ro.build.version.security_patch") report.securityPatchLevel = std::string(value);
            else if (key == "ro.build.date") report.buildDate = std::string(value);
            else if (key == "persist.sys.magisk.version") {
                std::string version_val(value);
                report.magiskVersion = version_val;
                std::string report_str = "Magisk property detected (Version: " + version_val + ")";
                if (version_val.find("alpha") != std::string::npos) {
                    report_str += " [Alpha]";
                }
                if (report.detections[DetectionCategory::RootAndFrameworks].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
            else if (key == "ro.lspose.version") {
                std::string report_str = "LSPosed property detected (Version: " + std::string(value) + ")";
                if (report.detections[DetectionCategory::RootAndFrameworks].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
            else if (key.rfind("ro.pif", 0) == 0) {
                std::string report_str = "Play Integrity Fix property detected: " + std::string(key);
                if (report.detections[DetectionCategory::RootHidingAndEvasion].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        void SystemPropertyRule::finalize(ReportData& report, AnalysisContext& context) {
            if (!report.buildFingerprint.empty() && !report.brand.empty()) {
                std::string fp_brand_part = report.buildFingerprint.substr(0, report.buildFingerprint.find('/'));
                std::string lower_brand = report.brand;
                std::transform(lower_brand.begin(), lower_brand.end(), lower_brand.begin(), [](unsigned char c){ return std::tolower(c); });
                std::transform(fp_brand_part.begin(), fp_brand_part.end(), fp_brand_part.begin(), [](unsigned char c){ return std::tolower(c); });
                if (fp_brand_part != lower_brand) {
                    std::string report_str = "Build Spoofing: Brand '" + report.brand + "' does not match fingerprint's brand part '" + report.buildFingerprint.substr(0, report.buildFingerprint.find('/')) + "'.";
                    if (report.detections[DetectionCategory::RootHidingAndEvasion].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }
            if (!report.securityPatchLevel.empty() && report.buildDate.find("20") == 0) {
                try {
                    int build_year = std::stoi(report.buildDate.substr(0, 4));
                    int build_month = std::stoi(report.buildDate.substr(5, 2));
                    int patch_year = std::stoi(report.securityPatchLevel.substr(0, 4));
                    int patch_month = std::stoi(report.securityPatchLevel.substr(5, 2));
                    if (patch_year > build_year || (patch_year == build_year && patch_month > build_month + 2)) {
                        std::string report_str = "Security Patch Level Anomaly: Patch date (" + report.securityPatchLevel + ") is significantly newer than build date (" + report.buildDate.substr(0, 10) + ").";
                        if (report.detections[DetectionCategory::RootHidingAndEvasion].insert(report_str).second) {
                            report.totalScore += getScore(report_str);
                        }
                    }
                } catch (...) {}
            }
        }
        
        int SystemPropertyRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Magisk property detected") != std::string::npos) return 4;
            if (detectionMessage.find("LSPosed property detected") != std::string::npos) return 4;
            if (detectionMessage.find("Play Integrity Fix property detected") != std::string::npos) return 3;
            if (detectionMessage.find("Build Spoofing") != std::string::npos) return 2;
            if (detectionMessage.find("Security Patch Level Anomaly") != std::string::npos) return 1;
            return 0;
        }

        std::vector<std::string> BootloaderStateRule::getTargetSections() const { return {"KERNEL LOG", "LAST KMSG", "SYSTEM PROPERTIES"}; }
        DetectionCategory BootloaderStateRule::getTargetCategory() const { return DetectionCategory::SuspiciousProperties; }
        
        void BootloaderStateRule::processLine(std::string_view line, ReportData& report, AnalysisContext& context) {
            if (context.bootloaderStateConfirmedByKernel) {
                return;
            }

            std::string_view found_value;
            bool is_kernel_truth = false;

            if (line.find("androidboot.vbmeta.device_state=unlocked") != std::string_view::npos ||
                line.find("androidboot.lock_state=unlocked") != std::string_view::npos) {
                found_value = "unlocked (cmdline)";
                is_kernel_truth = true;
            } else if (line.find("SELinux: a new context") != std::string_view::npos && line.find("has been loaded") != std::string_view::npos) {
                found_value = "unlocked (sepolicy)";
                is_kernel_truth = true;
            } else if (line.find("Device locked: false") != std::string_view::npos ||
                       line.find("KM_VERIFIED_BOOT_UNVERIFIED") != std::string_view::npos) {
                found_value = "unlocked";
            }

            const std::string_view key_kernel_verified = "androidboot.verifiedbootstate=";
            size_t pos = line.find(key_kernel_verified);
            if (pos != std::string_view::npos) {
                std::string_view value_part = line.substr(pos + key_kernel_verified.length());
                size_t end_pos = value_part.find(' ');
                std::string_view state = value_part.substr(0, end_pos);
                if (state != "green") {
                    found_value = state;
                }
            }

            std::string_view prop_key, prop_value;
            parse_property_line(line, prop_key, prop_value);
            if (!prop_key.empty()) {
                if (prop_key == "ro.boot.flash.locked" && (prop_value == "0" || prop_value == "no")) {
                    found_value = "orange";
                } else if (prop_key == "ro.boot.real_oem_unlock_mode" && (prop_value == "1" || prop_value == "true")) {
                    found_value = "orange";
                } else if (prop_key == "ro.boot.verifiedbootstate" && prop_value != "green") {
                    found_value = prop_value;
                }
            }

            if (found_value.empty()) {
                if (!prop_key.empty()) {
                    if ((prop_key == "ro.boot.flash.locked" && prop_value != "0" && prop_value != "no") ||
                        (prop_key == "ro.boot.real_oem_unlock_mode" && prop_value != "1" && prop_value != "true") ||
                        (prop_key == "ro.boot.verifiedbootstate" && prop_value == "green")) {
                        found_value = "green";
                    }
                }
                pos = line.find(key_kernel_verified);
                if (pos != std::string_view::npos) {
                    std::string_view value_part = line.substr(pos + key_kernel_verified.length());
                    size_t end_pos = value_part.find(' ');
                    if (value_part.substr(0, end_pos) == "green") {
                        found_value = "green";
                    }
                }
            }

            if (!found_value.empty()) {
                if (is_kernel_truth) {
                    context.verifiedBootState = std::string(found_value);
                    context.bootloaderStateConfirmedByKernel = true;
                } else if (found_value != "green") {
                    context.verifiedBootState = std::string(found_value);
                } else if (context.verifiedBootState.empty()) {
                    context.verifiedBootState = "green";
                }
            }
        }

        void BootloaderStateRule::finalize(ReportData& report, AnalysisContext& context) {
            if (!context.verifiedBootState.empty()) {
                if (context.verifiedBootState == "green") {
                    report.bootloaderStatus = "Заблокирован (green)";
                } else {
                    report.bootloaderStatus = "Разблокирован (" + context.verifiedBootState + ")";
                }
            }
        }
        int BootloaderStateRule::getScore(const std::string&) const { return 0; }

        std::vector<std::string> SuspiciousPropertiesRule::getTargetSections() const { return {"SYSTEM PROPERTIES", "LOGCAT"}; }
        DetectionCategory SuspiciousPropertiesRule::getTargetCategory() const { return DetectionCategory::SuspiciousProperties; }
        
        void SuspiciousPropertiesRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            std::string_view key, value;
            parse_property_line(line, key, value);
            if (key.empty()) return;
            std::string report_str;
            if (key == "ro.debuggable" && value == "1") {
                report_str = "System is debuggable (ro.debuggable=1).";
            } else if (key == "ro.secure" && value == "0") {
                report_str = "System is insecure (ro.secure=0).";
            } else if (key == "service.adb.root" && value == "1") {
                report_str = "ADB is running as root by default (service.adb.root=1).";
            } else if (key == "persist.sys.usb.config" && value.find("adb") != std::string_view::npos) {
                report_str = "Developer Options: USB Debugging is enabled.";
            } else if (key == "sys.oem_unlock_allowed" && value == "1") {
                report_str = "Developer Options: OEM Unlocking is allowed.";
            } else if (key == "ro.build.tags" && value != "release-keys") {
                report_str = "Build Tags: System is signed with non-production keys ('" + std::string(value) + "').";
            } else if (key == "ro.kernel.qemu" && value == "1") {
                report_str = "Emulator property 'ro.kernel.qemu' is set.";
            } else if (key == "ro.hardware" && (value == "goldfish" || value == "ranchu")) {
                report_str = "Emulator property 'ro.hardware' is set to '" + std::string(value) + "'.";
            } else if (key == "ro.dalvik.vm.native.bridge" && value != "0") {
                report_str = "Native Bridge is active ('" + std::string(value) + "'), may indicate emulator or compatibility layer.";
            }

            if (!report_str.empty()) {
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int SuspiciousPropertiesRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("debuggable=1") != std::string::npos) return 1;
            if (detectionMessage.find("secure=0") != std::string::npos) return 4;
            if (detectionMessage.find("adb.root=1") != std::string::npos) return 5;
            if (detectionMessage.find("USB Debugging is enabled") != std::string::npos) return 1;
            if (detectionMessage.find("OEM Unlocking is allowed") != std::string::npos) return 1;
            if (detectionMessage.find("non-production keys") != std::string::npos) return 2;
            if (detectionMessage.find("Emulator property") != std::string::npos) return 5;
            if (detectionMessage.find("Native Bridge is active") != std::string::npos) return 3;
            return 0;
        }
    }
}
