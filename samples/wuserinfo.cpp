/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file demonstrates use of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#include <pwd.h>
#include <grp.h>

#include <cassert>
#include <cstdio>
#include <string>

#include <windows.h> // envvars

void DisplayUserRecord(const struct passwd & u_rec) {
    std::fprintf(stdout, "User name: %s\n", u_rec.pw_name);
    std::fprintf(stdout, "Full name: %s\n", u_rec.pw_gecos);
    std::fprintf(stdout, "UID:GID=%u:%u\n", u_rec.pw_uid, u_rec.pw_gid);
    std::fprintf(stdout, "Pass hash: %s\n", u_rec.pw_passwd);
    std::fprintf(stdout, "Privilege: %s\n", u_rec.pw_class);
    std::fprintf(stdout, "User home: %s\n", u_rec.pw_dir);
    std::fprintf(stdout, "Def shell: %s\n", u_rec.pw_shell);

    // times are Unix epoch here; 0xffffffff (~0) means Forever
    // further conversion is left as an exercise for the reader
    std::fprintf(stdout, "Acc until: %lld\n", u_rec.pw_expire);
    std::fprintf(stdout, "Pwd until: %lld\n", u_rec.pw_change);
    std::fprintf(stdout, "\n");
}

int main(int argc, char** argv) {

    bool show_help = false;
    bool show_list = false;
    bool log_tests = false;
    bool show_dflt = false;

    // TODO/nth: pass custom uname or uid
    for(int argi = 1; argi < argc; ++argi) {
        if(argv[argi] && '/' == *argv[argi]) {
            char opt = argv[argi][1];
            show_help |= 'h' == opt;
            show_list |= 'a' == opt;
            log_tests |= 't' == opt;
            show_dflt |= 'd' == opt;
        }
    }

    if(show_help) std::fprintf(stdout,
R"NOMOREHELP(
This sample command-line tool uses POSIX APIs implemented on Windows (2000+)
with libwusers to display account information on the local Windows machine.

Usage:
    wuserinfo.exe [/h] [/a] [/t] [/d]

The meaning of the switches is as follows:

    /d  display default users (Administrator and Guest)
    /a  enumerate all user accounts
    /t  display test log messages ("this feature works! this, too!")
    /h  display this help

    By default, only current account information is displayed.

wuserinfo.exe and libwusers.dll are public domain worldwide -- both in binary
and source code. They are free to use and abuse by anyone and for any purpose,
for-profit use and abuse included.

Further reading: https://github.com/treeswift/libwusers

)NOMOREHELP");

    std::string uname(MAX_PATH, L'\0');
    std::size_t u_len = ExpandEnvironmentStringsA("%USERNAME%", &uname[0], uname.size());
    assert(u_len < MAX_PATH);
    uname.resize(u_len, L'\0');

    const struct passwd & u_rec = *getpwnam(uname.c_str());
    DisplayUserRecord(u_rec);

    uid_t last_uid = u_rec.pw_uid;
    uid_t dupl_uid = ~0;
    assert(!uid_from_user(uname.c_str(), &dupl_uid));
    assert(last_uid == dupl_uid);
    if(log_tests) std::fprintf(stdout, "tests passed: uid_from_user()\n");

    std::string outbuf(10, '\0');
    struct passwd out_pwd;
    struct passwd * out_ptr = nullptr;
    assert(getpwnam_r(uname.c_str(), &out_pwd, &outbuf[0], outbuf.size(), &out_ptr));
    assert(!out_ptr);
    outbuf.resize(32767, '\0');
    assert(!getpwnam_r(uname.c_str(), &out_pwd, &outbuf[0], outbuf.size(), &out_ptr));
    assert(out_ptr == &out_pwd);
    assert(!strcmp(out_pwd.pw_gecos, u_rec.pw_gecos));
    if(log_tests) std::fprintf(stdout, "tests passed: getpwnam_r()\n");

    auto copy_a = pw_dup(&u_rec);
    auto copy_b = pw_dup(&u_rec);
    auto copy_c = pw_dup(copy_a);

    assert(Equal(*u_rec, *copy_a));
    assert(Equal(*u_rec, *copy_b));
    assert(Equal(*u_rec, *copy_c));

    // beware: assuming pw_shell is copied last. see `pwd.cpp`
    std::size_t combo_sz = copy_c->pw_shell - reinterpret_cast<char*>(copy_c) + std::strlen(copy_c->pw_shell);

    auto PChrToOffs = [](struct passwd* pwd) {
        uintptr_t pwo = reinterpret_cast<uintptr_t>(pwd);
        auto to_off = [pwo](char*& fld){ if(fld) fld -= pwo; };
        to_off(pwd->pw_name);
        to_off(pwd->pw_passwd);
        to_off(pwd->pw_class);
        to_off(pwd->pw_gecos);
        to_off(pwd->pw_dir);
        to_off(pwd->pw_shell);
    };

    PChrToOffs(copy_b);
    PChrToOffs(copy_c);
    assert(!memcmp(copy_b, copy_c, combo_sz));
    if(log_tests) std::fprintf(stdout, "tests passed: pw_dup()\n\n");

    // enumeration API; overwrites u_rec, but it's copied to copy_a
    if(show_list) {
        std::size_t user_count = 0u;
        setpwent();
        assert(!errno);
        struct passwd* cursor;
        while((cursor = getpwent())) {
            std::fprintf(stdout, "# enumerating user database: user# %u\n", ++user_count);
            DisplayUserRecord(*cursor);
            if(copy_a->pw_uid == cursor->pw_uid) {
                assert(copy_a->pw_gid == cursor->pw_gid); // primary group id must match
                assert(!strcmp(copy_a->pw_gecos, cursor->pw_gecos)); // contact must match
            }
        }
        endpwent();
        std::fprintf(stdout, "==== total entries in user database: %u\n\n", user_count);
    }

    if(show_dflt) {
        std::fprintf(stdout, "Default accounts with well-known RIDs:\n\n");

        constexpr const uid_t ADMIN = 500;
        constexpr const uid_t GUEST = 501;
        constexpr const uid_t GENIE = ~0u;
        struct passwd* admin_ptr = getpwuid(ADMIN);
        DisplayUserRecord(*admin_ptr);
        assert(!errno);
        assert(!stricmp(admin_ptr->pw_class, "Administrator"));

        struct passwd guest_pwd;
        std::string guest_chars(32767, '\0');
        struct passwd* guest_ptr;
        int retval = getpwuid_r(GUEST, &guest_pwd, &guest_chars[0], guest_chars.size(), &guest_ptr);
        assert(!retval);

        DisplayUserRecord(guest_pwd);
        assert(guest_ptr == &guest_pwd);
        assert(!stricmp(guest_pwd.pw_class, "Guest"));

        // once again please. request the guest (which isn't in the entry cache), then the admin (which currently is)
        std::string admin_name_cc(admin_ptr->pw_name);
        const char* guest_name = user_from_uid(GUEST, 0);
        assert(!strcmp(guest_name, guest_pwd.pw_name));
        const char* admin_name = user_from_uid(ADMIN, 0);
        assert(!strcmp(admin_name, admin_name_cc));
        const char* genie_name = user_from_uid(GENIE, 0);
        assert(!strcmp(genie_name, "4294967295")); // uid
        genie_name = user_from_uid(GENIE, 22 /*nouser*/);
        assert(!genie_name); // nonexistent => nullptr
        if(log_tests) std::fprintf(stdout, "tests passed: all!\n\n");
    }

    return 0;
}