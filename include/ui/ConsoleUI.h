#pragma once

#include "Common.h"
#include "platform/Platform.h"
#include "core/Core.h"

namespace UI {
    using namespace Core;

    class ConsoleUI {
    private:
        const Platform::IConsole& console_;

    public:
        ConsoleUI(const Platform::IConsole& console);
        enum class MainMenuOption { AnalyzeRelease, AnalyzeDebug, Exit, Invalid };

        MainMenuOption displayMainMenu() const;
        std::optional<fs::path> selectFile(const std::string& title, const std::vector<fs::path>& items) const;
        std::optional<fs::path> promptForManualPath() const;
        void showMessage(const std::string& msg, bool pause = false) const;
        void displayResults(const Core::ReportData& data, bool isDebug) const;
    };
}
