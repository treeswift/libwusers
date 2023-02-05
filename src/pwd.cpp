/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#include <pwd.h>

#ifdef __cplusplus
extern "C" {
#endif

namespace {
static thread_local int curr_recid;
}

struct passwd *getpwuid(uid_t) {
	//
	return nullptr;
}

struct passwd *getpwnam(const TCHAR *) {
	//
	return nullptr;
}

struct passwd *getpwuid_shadow(uid_t) {
	//
	return nullptr;
}

struct passwd *getpwnam_shadow(const TCHAR *) {
	//
	return nullptr;
}

int getpwnam_r(const TCHAR *, struct passwd *, TCHAR *, size_t, struct passwd **) {
	//
	return 0;
}

int getpwuid_r(uid_t, struct passwd *, TCHAR *, size_t, struct passwd **) {
	//
	return 0;
}

#if __BSD_VISIBLE || __XPG_VISIBLE
void setpwent(void) {
	//
}

struct passwd *getpwent(void) {
	//
	return nullptr;
}

void endpwent(void) {
	//
}
#endif

#if __BSD_VISIBLE
int setpassent(int) {
	//
	return 0;
}

int uid_from_user(const TCHAR *, uid_t *) {
	//
	return 0;
}

const TCHAR *user_from_uid(uid_t, int) {
	//
	return _T("");
}

TCHAR *bcrypt_gensalt(uint8_t) {
	//
	return nullptr;
}

TCHAR *bcrypt(const TCHAR *, const TCHAR *) {
	//
	return nullptr;
}

int bcrypt_newhash(const TCHAR *, int, TCHAR *, size_t) {
	//
	return 0;
}

int bcrypt_checkpass(const TCHAR *, const TCHAR *) {
	//
	return 0;
}

struct passwd *pw_dup(const struct passwd *) {
	//
	return nullptr;
}
#endif

#ifdef __cplusplus
}
#endif
