#include "password_dialog.h"
#include "resource.h"

#include <windowsx.h>

namespace dmg {
namespace {

INT_PTR CALLBACK PasswordDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG: {
            auto* p = reinterpret_cast<PasswordPrompt*>(lParam);
            SetWindowLongPtrW(hDlg, GWLP_USERDATA, lParam);
            SetDlgItemTextW(hDlg, IDC_PW_FILE, p->fileName.c_str());
            SetDlgItemTextW(hDlg, IDC_PW_DETAIL, p->detail.c_str());
            CheckDlgButton(hDlg, IDC_PW_REMEMBER, p->remember ? BST_CHECKED : BST_UNCHECKED);
            std::wstring status;
            if (p->attempt > 1) {
                status = p->lastError.empty() ? L"Password not accepted" : p->lastError;
                status += L" (attempt " + std::to_wstring(p->attempt) + L" of " + std::to_wstring(p->maxAttempts) + L")";
            }
            SetDlgItemTextW(hDlg, IDC_PW_STATUS, status.c_str());
            SendDlgItemMessageW(hDlg, IDC_PW_EDIT, EM_LIMITTEXT, 1024, 0);
            SetFocus(GetDlgItem(hDlg, IDC_PW_EDIT));
            return FALSE;   // we set focus ourselves
        }
        case WM_CTLCOLORSTATIC: {
            if (reinterpret_cast<HWND>(lParam) == GetDlgItem(hDlg, IDC_PW_STATUS)) {
                HDC hdc = reinterpret_cast<HDC>(wParam);
                SetTextColor(hdc, RGB(200, 0, 0));
                SetBkMode(hdc, TRANSPARENT);
                return reinterpret_cast<INT_PTR>(GetSysColorBrush(COLOR_BTNFACE));
            }
            return FALSE;
        }
        case WM_COMMAND: {
            auto* p = reinterpret_cast<PasswordPrompt*>(GetWindowLongPtrW(hDlg, GWLP_USERDATA));
            switch (LOWORD(wParam)) {
                case IDC_PW_SHOW: {
                    HWND edit = GetDlgItem(hDlg, IDC_PW_EDIT);
                    bool show = IsDlgButtonChecked(hDlg, IDC_PW_SHOW) == BST_CHECKED;
                    SendMessageW(edit, EM_SETPASSWORDCHAR, show ? 0 : static_cast<WPARAM>(L'\x25CF'), 0);
                    InvalidateRect(edit, nullptr, TRUE);
                    return TRUE;
                }
                case IDOK: {
                    wchar_t buf[1025] = {};
                    GetDlgItemTextW(hDlg, IDC_PW_EDIT, buf, 1024);
                    p->password = buf;
                    p->remember = IsDlgButtonChecked(hDlg, IDC_PW_REMEMBER) == BST_CHECKED;
                    SecureZeroMemory(buf, sizeof(buf));
                    EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
            }
            return FALSE;
        }
    }
    return FALSE;
}

} // namespace

bool ShowPasswordDialog(HINSTANCE hInst, HWND parent, PasswordPrompt& p) {
    INT_PTR rc = DialogBoxParamW(hInst, MAKEINTRESOURCEW(IDD_PASSWORD), parent, PasswordDlgProc, reinterpret_cast<LPARAM>(&p));
    return rc == IDOK;
}

} // namespace dmg
