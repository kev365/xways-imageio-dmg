#include "dmg_plist.h"
#include "dmg_util.h"

#include <string_view>

namespace dmg {
namespace {

using sv = std::string_view;

bool IsSpace(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

sv Trim(sv s) {
    while (!s.empty() && IsSpace(s.front())) s.remove_prefix(1);
    while (!s.empty() && IsSpace(s.back())) s.remove_suffix(1);
    return s;
}

void AppendUtf8(std::string& out, unsigned long cp) {
    if (cp < 0x80) { out.push_back(static_cast<char>(cp)); return; }
    if (cp < 0x800) { out.push_back(static_cast<char>(0xC0 | (cp >> 6))); }
    else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    }
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
}

std::string DecodeEntities(sv s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '&') { out.push_back(s[i]); continue; }
        size_t semi = s.find(';', i);
        if (semi == sv::npos) { out.push_back('&'); continue; }
        sv ent = s.substr(i + 1, semi - i - 1);
        if      (ent == "amp")  out.push_back('&');
        else if (ent == "lt")   out.push_back('<');
        else if (ent == "gt")   out.push_back('>');
        else if (ent == "quot") out.push_back('"');
        else if (ent == "apos") out.push_back('\'');
        else if (!ent.empty() && ent[0] == '#') {
            std::string num(ent.substr(1));
            unsigned long cp = (!num.empty() && (num[0] == 'x' || num[0] == 'X'))
                ? std::strtoul(num.c_str() + 1, nullptr, 16)
                : std::strtoul(num.c_str(), nullptr, 10);
            AppendUtf8(out, cp);
        } else {
            out.append(s.substr(i, semi - i + 1));
        }
        i = semi;
    }
    return out;
}

// Reads the next element starting at or after `from`. Returns its tag name,
// its body (empty for <tag/> forms), and advances `from` past it.
bool NextElement(sv s, size_t& from, std::string& tag, sv& body) {
    size_t a = s.find('<', from);
    if (a == sv::npos) return false;
    size_t gt = s.find('>', a);
    if (gt == sv::npos) return false;
    sv inside = s.substr(a + 1, gt - a - 1);
    bool selfClosing = !inside.empty() && inside.back() == '/';
    if (selfClosing) inside.remove_suffix(1);
    // tag name = up to first space
    size_t sp = inside.find(' ');
    tag = std::string(sp == sv::npos ? inside : inside.substr(0, sp));
    if (selfClosing) { body = sv(); from = gt + 1; return true; }
    std::string closeTag = "</" + tag + ">";
    size_t c = s.find(closeTag, gt + 1);
    if (c == sv::npos) return false;
    body = s.substr(gt + 1, c - gt - 1);
    from = c + closeTag.size();
    return true;
}

// Finds the next <dict> ... </dict> at the current level. Returns npos when
// the enclosing </array> is reached first.
size_t NextDict(sv s, size_t from, size_t& dictEnd) {
    size_t d = s.find("<dict", from);
    size_t e = s.find("</array>", from);
    if (d == sv::npos || (e != sv::npos && e < d)) return sv::npos;
    size_t pos = d + 5;
    int depth = 1;
    while (depth > 0) {
        size_t o = s.find("<dict", pos);
        size_t c = s.find("</dict>", pos);
        if (c == sv::npos) return sv::npos;
        if (o != sv::npos && o < c) { ++depth; pos = o + 5; }
        else { --depth; pos = c + 7; }
    }
    dictEnd = pos;
    return d;
}

} // namespace

bool ParseBlkxPlist(const char* xml, size_t n, std::vector<BlkxEntry>& out, std::string& err) {
    sv s(xml, n);
    out.clear();
    if (s.find("<plist") == sv::npos) { err = "no <plist> element"; return false; }

    // Locate <key>blkx</key>.
    size_t k = sv::npos, from = 0;
    for (;;) {
        size_t p = s.find("<key>", from);
        if (p == sv::npos) break;
        size_t q = s.find("</key>", p);
        if (q == sv::npos) break;
        if (Trim(s.substr(p + 5, q - p - 5)) == "blkx") { k = q + 6; break; }
        from = q + 6;
    }
    if (k == sv::npos) { err = "plist has no blkx key"; return false; }
    size_t arr = s.find("<array", k);
    if (arr == sv::npos) { err = "blkx key not followed by <array>"; return false; }
    size_t pos = s.find('>', arr);
    if (pos == sv::npos) { err = "malformed <array>"; return false; }
    ++pos;

    for (;;) {
        size_t dictEnd = 0;
        size_t d = NextDict(s, pos, dictEnd);
        if (d == sv::npos) break;
        sv dict = s.substr(d, dictEnd - d);
        BlkxEntry e;
        std::string cfname;
        size_t dp = dict.find('>');           // skip the <dict> open tag
        if (dp == sv::npos) break;
        ++dp;
        for (;;) {
            std::string tag; sv body;
            if (!NextElement(dict, dp, tag, body)) break;
            if (tag == "/dict") break;
            if (tag != "key") continue;
            sv key = Trim(body);
            std::string vtag; sv vbody;
            if (!NextElement(dict, dp, vtag, vbody)) break;
            if (vtag == "string") {
                std::string val = DecodeEntities(vbody);
                if (key == "Name") e.name = val;
                else if (key == "CFName") cfname = val;
                else if (key == "Attributes") e.attributes = val;
                else if (key == "ID") e.id = std::strtoll(val.c_str(), nullptr, 10);
            } else if (vtag == "integer") {
                if (key == "ID") e.id = std::strtoll(std::string(vbody).c_str(), nullptr, 10);
            } else if (vtag == "data") {
                if (key == "Data" && !Base64Decode(vbody.data(), vbody.size(), e.mish)) {
                    err = "blkx Data is not valid base64";
                    return false;
                }
            }
            // other value kinds (true/false/date/nested) are skipped by NextElement
        }
        if (e.name.empty()) e.name = cfname;
        if (!e.mish.empty()) out.push_back(std::move(e));
        pos = dictEnd;
    }
    if (out.empty()) { err = "blkx array has no entries with Data"; return false; }
    return true;
}

} // namespace dmg
