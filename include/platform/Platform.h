#pragma once

#include "Common.h"

namespace Platform {
    struct KeyPress { 
        enum { None, Char, Left, Right, Enter, Backspace } key = None; 
        char value = '\0'; 
    };

    class IConsole { 
    public: 
        virtual ~IConsole() = default; 
        virtual void clear() const = 0; 
        virtual KeyPress get_key_press() const = 0; 
        virtual void write(std::string_view s) const = 0; 
        virtual std::string read_line() const = 0; 
    };

    #ifdef _WIN32
    class WindowsConsole : public IConsole { 
    public: 
        void clear() const override; 
        void write(std::string_view s) const override; 
        KeyPress get_key_press() const override; 
        std::string read_line() const override; 
    };
    #else
    class LinuxConsole : public IConsole {
    private:
        struct TermiosGuard {
            termios original;
            TermiosGuard();
            ~TermiosGuard();
        };
    public:
        void clear() const override;
        void write(std::string_view s) const override;
        KeyPress get_key_press() const override;
        std::string read_line() const override;
    };
    #endif

    inline std::unique_ptr<IConsole> create_console() {
    #ifdef _WIN32
        return std::make_unique<WindowsConsole>();
    #else
        return std::make_unique<LinuxConsole>();
    #endif
    }
}
