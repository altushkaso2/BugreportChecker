#include "platform/Platform.h"

namespace Platform {

#ifdef _WIN32
    void WindowsConsole::clear() const { system("cls"); }
    void WindowsConsole::write(std::string_view s) const { std::cout << s << std::flush; }
    KeyPress WindowsConsole::get_key_press() const { 
        int ch = _getch(); 
        if (ch == 224) { 
            switch (_getch()) { 
                case 75: return {KeyPress::Left}; 
                case 77: return {KeyPress::Right}; 
            } 
        } else if (ch == 13) return {KeyPress::Enter}; 
        else if (ch == 8) return {KeyPress::Backspace}; 
        return {KeyPress::Char, (char)ch}; 
    }
    std::string WindowsConsole::read_line() const { 
        std::string line; 
        while(true) { 
            KeyPress press = get_key_press(); 
            if (press.key == KeyPress::Enter) { std::cout << "\n"; return line; } 
            if (press.key == KeyPress::Backspace) { 
                if (!line.empty()) { line.pop_back(); std::cout << "\b \b" << std::flush; } 
            } else if (press.key == KeyPress::Char) { 
                line += press.value; std::cout << press.value << std::flush; 
            } 
        } 
    }
#else
    LinuxConsole::TermiosGuard::TermiosGuard() { tcgetattr(STDIN_FILENO, &original); }
    LinuxConsole::TermiosGuard::~TermiosGuard() { tcsetattr(STDIN_FILENO, TCSANOW, &original); }
    
    void LinuxConsole::clear() const { system("clear"); }
    void LinuxConsole::write(std::string_view s) const { std::cout << s << std::flush; }
    KeyPress LinuxConsole::get_key_press() const {
        TermiosGuard guard;
        termios newt = guard.original;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        char c1 = '\0';
        if (read(STDIN_FILENO, &c1, 1) <= 0) return {KeyPress::None};
        if (c1 == '\033') {
            char seq[2];
            if (read(STDIN_FILENO, &seq[0], 1) > 0 && seq[0] == '[') {
                if (read(STDIN_FILENO, &seq[1], 1) > 0) {
                    if (seq[1] == 'C') return {KeyPress::Right};
                    if (seq[1] == 'D') return {KeyPress::Left};
                }
            }
        } else if (c1 == '\n' || c1 == '\r') return {KeyPress::Enter};
        else if (c1 == 127) return {KeyPress::Backspace};
        return {KeyPress::Char, c1};
    }
    std::string LinuxConsole::read_line() const {
        std::string line;
        while(true) {
            KeyPress press = get_key_press();
            if (press.key == KeyPress::Enter) { std::cout << "\n"; return line; }
            if (press.key == KeyPress::Backspace) {
                if (!line.empty()) { line.pop_back(); std::cout << "\b \b" << std::flush; }
            } else if (press.key == KeyPress::Char) {
                line += press.value; std::cout << press.value << std::flush;
            }
        }
    }
#endif
}
