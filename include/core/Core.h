#pragma once

#include "Common.h"

namespace Core {
    enum class DetectionCategory {
        RootAndFrameworks, RootHidingAndEvasion, FileSystemAndMounts,
        SuspiciousProperties, Anomalies, CustomBuild, AnomalousLogs,
        ProhibitedPackages, AppAnalysis
    };

    class ReportData {
    public:
        std::string model;
        std::string androidVersion;
        std::string buildFingerprint;
        std::string bootloaderStatus;
        std::string magiskVersion;
        std::string serialNumber;
        std::string brand;
        std::string device;
        std::string securityPatchLevel;
        std::string buildDate;
        std::string seLinuxStatus = "Could not determine";
        std::map<DetectionCategory, std::set<std::string>> detections;
        std::vector<std::string> debugLog;
        int totalScore = 0;

        [[nodiscard]] std::string getLogFilename() const {
            std::string safe_model = model.empty() ? "unknown_model" : model;
            std::replace_if(safe_model.begin(), safe_model.end(),
                [](unsigned char c) { return !(std::isalnum(c) || c == '-'); }, '_');
            return safe_model + "_log.txt";
        }
    };

    struct AnalysisContext {
        enum class SELinuxState { Enforcing, Permissive };
        SELinuxState seLinuxState = SELinuxState::Enforcing;

        std::optional<int> magiskd_pid;
        std::optional<int> zygote_ppid;
        std::string current_package_name;
        std::string current_seinfo;
        std::set<std::string> suspicious_root_procs;
        int selinux_denial_count = 0;
        int zygote_fork_count = 0;
        std::string last_pid_dump;
        std::vector<std::string>* debugLogPtr = nullptr;
        std::string verifiedBootState;
        bool bootloaderStateConfirmedByKernel = false;
        std::string lastDetectedFramework;
        std::set<std::string> reported_log_threats;
    };
}
