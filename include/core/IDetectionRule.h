#pragma once

#include "Common.h"
#include "Core.h"

namespace Core {
    class IDetectionRule {
    public:
        virtual ~IDetectionRule() = default;
        virtual std::vector<std::string> getTargetSections() const = 0;
        virtual void processLine(std::string_view line, ReportData& report, AnalysisContext& context) = 0;
        virtual void finalize(ReportData& report, AnalysisContext& context) {}
        virtual int getScore(const std::string& detectionMessage) const = 0;
        virtual DetectionCategory getTargetCategory() const = 0;
    };
}
