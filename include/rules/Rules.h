#pragma once

#include "Common.h"
#include "core/IDetectionRule.h"

namespace Core {
    namespace Rules {

        void parse_property_line(std::string_view line, std::string_view& out_key, std::string_view& out_value);

        class SystemPropertyRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext& context) override;
            void finalize(ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class BootloaderStateRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext& context) override;
            void finalize(ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string&) const override;
        };

        class PackageManagerRule : public IDetectionRule {
        private:
            bool is_hidden = false;
            void process_current_package(ReportData& report, AnalysisContext& context);
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext& context) override;
            void finalize(ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class ProhibitedPackagesRule : public IDetectionRule {
        private:
            const std::map<std::string, std::pair<std::string, DetectionCategory>> threat_lexicon;
        public:
            ProhibitedPackagesRule();
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class LogKeywordRule : public IDetectionRule {
        private:
            const std::vector<std::tuple<std::string, std::string, int, DetectionCategory>> threat_lexicon;
        public:
            LogKeywordRule();
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string&) const override;
        };

        class ZygoteParentRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData&, AnalysisContext& context) override;
            void finalize(ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class RootActivityRule : public IDetectionRule {
        private:
            const std::set<std::string_view> whitelist;
            const std::set<std::string_view> blacklist;
        public:
            RootActivityRule();
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext& context) override;
            void finalize(ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class InvalidSelinuxTransitionRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class SelinuxNeverallowRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class SelinuxDenialSpamRule : public IDetectionRule {
        private:
            const int SPAM_THRESHOLD = 100;
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData&, AnalysisContext& context) override;
            void finalize(ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class SelinuxContextRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class SELinuxStateRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData&, AnalysisContext& context) override;
            void finalize(ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class CustomSePolicyRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class DmVerityRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class KernelRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class MountAnalysisRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class RemountRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class AdvancedFsRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class MagiskModulesRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class AppRootUsageRule : public IDetectionRule {
        private:
            const std::regex su_log_regex;
        public:
            AppRootUsageRule();
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class CustomRecoveryRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class FilePermissionsRule : public IDetectionRule {
        private:
            const std::set<std::string_view> whitelist;
        public:
            FilePermissionsRule();
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class SuspiciousModulesRule : public IDetectionRule {
        private:
            const std::set<std::string_view> blacklist;
        public:
            SuspiciousModulesRule();
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class ResetpropRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class InitServiceRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class LinkerAnomalyRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class TracerPidRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class LoadedLibrariesRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class FrameworkRule : public IDetectionRule {
        private:
            const std::regex lsposed_version_regex;
            const std::regex lsposed_target_regex;
        public:
            FrameworkRule();
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class EnvironmentRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class KernelSuLogRule : public IDetectionRule {
        private:
            const std::regex susfs_regex;
            const std::regex init_regex;
        public:
            KernelSuLogRule();
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class UserSnippetRule : public IDetectionRule {
        private:
            const std::regex pid_dump_regex;
        public:
            UserSnippetRule();
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class SuspiciousBinaryRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class SuspiciousPropertiesRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class RunningServicesRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class ZygoteAnomalyRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class ZygoteForkSpamRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData&, AnalysisContext& context) override;
            void finalize(ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class InitRcRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class TombstoneRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class KeymasterLogRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext& context) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class TrickyStoreProcessRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

        class TrickyStoreLogRule : public IDetectionRule {
        public:
            std::vector<std::string> getTargetSections() const override;
            DetectionCategory getTargetCategory() const override;
            void processLine(std::string_view line, ReportData& report, AnalysisContext&) override;
            int getScore(const std::string& detectionMessage) const override;
        };

    }
}
