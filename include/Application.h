#pragma once

#include "Common.h"
#include "platform/Platform.h"
#include "ui/ConsoleUI.h"
#include "analyzer/ReportAnalyzer.h"
#include "core/Core.h"

#include <optional>
#include <vector>

class Application {
private:
    std::unique_ptr<Platform::IConsole> console_;
    UI::ConsoleUI ui_;
    Core::ReportAnalyzer analyzer_;

    std::vector<fs::path> findBugReports() const;
    void handleAnalysis(bool isDebug, std::optional<fs::path> initial_path = std::nullopt);

public:
    Application();
    void run(int argc, char* argv[]);
};
