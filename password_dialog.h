// password_dialog.h — modal password prompt for encrypted DMGs.
#pragma once

#include <windows.h>
#include <string>

namespace dmg {

struct PasswordPrompt {
    std::wstring fileName;      // shown in the dialog
    std::wstring detail;        // cipher summary line
    int attempt = 1;
    int maxAttempts = 3;
    std::wstring lastError;     // "" on the first attempt
    // out
    std::wstring password;
    bool remember = true;
};

// Returns false when the analyst cancels.
bool ShowPasswordDialog(HINSTANCE hInst, HWND parent, PasswordPrompt& p);

} // namespace dmg
