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
    assert(!strcmp(out_pwd.pw_full_name, u_rec.pw_full_name));
    std::fprintf(stderr, "getpwnam_r() tests passed\n");

    // TODO test the rest
    return 0;
}