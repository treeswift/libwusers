/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#include <grp.h>

#ifdef __cplusplus
extern "C" {
#endif

namespace {
static thread_local int curr_group;
}

struct group *getgrgid(gid_t) {
	//
	return nullptr;
}

struct group *getgrnam(const char *) {
	//
	return nullptr;
}

#if __BSD_VISIBLE || __XPG_VISIBLE
void setgrent(void) {
	//
}

struct group *getgrent(void) {
	//
	return nullptr;
}

void endgrent(void) {
	//
}
#endif

#if __BSD_VISIBLE || __POSIX_VISIBLE >= 199506 || __XPG_VISIBLE
int getgrgid_r(gid_t, struct group *, char *, size_t, struct group **) {
	return 0;
}

int getgrnam_r(const char *, struct group *, char *, size_t, struct group **) {
	return 0;
}
#endif

#if __BSD_VISIBLE
int setgroupent(int) {
	//
	return 0;
}

int gid_from_group(const char *, gid_t *) {
	//
	return 0;
}

const char *group_from_gid(gid_t, int) {
	//
	return "";
}
#endif

#ifdef __cplusplus
}
#endif
