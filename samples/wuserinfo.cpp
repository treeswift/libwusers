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

int main(int argc, char** argv) {
    // ASCII

    std::string uname(MAX_PATH, L'\0');
    std::size_t u_len = ExpandEnvironmentStringsA("%USERNAME%", &uname[0], uname.size());
    assert(u_len < MAX_PATH);
    uname.resize(u_len, L'\0');

    const struct passwd & u_rec = *getpwnam(uname.c_str());
    std::fprintf(stderr, "User name: %s\n", u_rec.pw_name);
    std::fprintf(stderr, "Full name: %s\n", u_rec.pw_gecos);
    std::fprintf(stderr, "UID:GID=%u:%u\n", u_rec.pw_uid, u_rec.pw_gid);
    std::fprintf(stderr, "Pass hash: %s\n", u_rec.pw_passwd);
    std::fprintf(stderr, "Privilege: %s\n", u_rec.pw_class);
    std::fprintf(stderr, "User home: %s\n", u_rec.pw_dir);
    std::fprintf(stderr, "Def shell: %s\n", u_rec.pw_shell);

    // TODO convert Unix epoch here; also, represent Forever
    std::fprintf(stderr, "Acc until: %lld\n", u_rec.pw_expire);
    std::fprintf(stderr, "Pwd until: %lld\n", u_rec.pw_change);
    std::fprintf(stderr, "\n");

    uid_t last_uid = u_rec.pw_uid;
    uid_t dupl_uid = ~0;
    assert(!uid_from_user(uname.c_str(), &dupl_uid));
    assert(last_uid == dupl_uid);
    std::fprintf(stderr, "uid_from_user() test passed\n");

    std::string outbuf(10, '\0');
    struct passwd out_pwd;
    struct passwd * out_ptr = nullptr;
    assert(getpwnam_r(uname.c_str(), &out_pwd, &outbuf[0], outbuf.size(), &out_ptr));
    assert(!out_ptr);
    outbuf.resize(32767, '\0');
    assert(!getpwnam_r(uname.c_str(), &out_pwd, &outbuf[0], outbuf.size(), &out_ptr));
    assert(out_ptr == &out_pwd);
    assert(!strcmp(out_pwd.pw_gecos, u_rec.pw_gecos));
    std::fprintf(stderr, "getpwnam_r() tests passed\n");

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
    std::fprintf(stderr, "pw_dup() tests passed\n");

    // TODO test the rest
    return 0;
}