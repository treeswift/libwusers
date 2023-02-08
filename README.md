# What is this?

`libwusers` provides a POSIX wrapper around Windows users/groups API. It defines `struct passwd` and `struct group`
and implements POSIX API functions such as `getuid`, `getgid`, `getgrgid`, `getgrnam`, `getpwnam`, `getpwuid` (the list is not meant to be exhaustive…)
with native Windows API calls. Its goal is to simplify porting of open source software into the Windows ecosystem without touching the [L]GPL tar baby 
of Cygwin/Msys. If you just hit _"fatal error: pwd.h: No such file or directory"_, welcome home.

`libwusers` is being developed with two runtime targets in mind: MinGW and pure Windows API. It means two things in practice:
* Our API dependencies are limited to the intersection of APIs provided by MinGW and native Windows SDKs;
* Our POSIX headers don't conflict with POSIX headers provided by MinGW (IOW, it's safe to install them into `$(PREFIX)/$(TARGET)/include`).

The `Netapi32.lib` interfaces involved are available [since Windows 2000](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum).
Since the primary consumer of `libwusers` is [Project Rakko](https://github.com/armdevvel), real world testing (somewhat) ensures at least Windows 8.1+ support
in desktop mode. The need for UWP support is subject to debate (you need tilde expansion in a host-agnostic container? really?);
technically, it should _at least_ be possible to inject simulated user data process-wide or on a per-thread basis. File an issue if you need it (or fork and code it).

# Technical notes

## Field translation logic

Windows APIs are `wchar_t*`. POSIX APIs are `char*`. It's possible to specify any code page supported by Windows, including "default for the current user", "default for the current thread" (apparently, it is a thing) and UTF-8; include `wusers/wuser_cpage.h` for that.

The LM for time is `time_t` (seconds since the Unix epoch). Therefore time values are returned verbatim.

There is no direct search by RID in Windows API. Instead of guessing the intermediate SID authorities (which would have been extremely fragile), libwusers simply iterates over existing accounts (starting with cached records) looking for a match.

### User information

`libwusers` converts from [USER_INFO_3](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_3) to [struct passwd](https://man.openbsd.org/getpwnam.3).

* `pw_name` is… well, the name. On Windows, it MAY contain spaces; make sure your project won't be confused. Queries by account name are case-insensitive.
* `pw_uid` and `pw_gid` are RIDs of the user and the user's primary group, respectively. WinXP APIs allow requesting SIDs instead of RIDs,
but only the last component (=RID) fits within POSIX types.
* `pw_gecos` is the user's full name.
* `pw_class` is the string representation of the privilege level, i.e. one of the three strings: "User", "Administrator" or "Guest".
* `pw_dir` is the user's profile folder. Since `NetUserGetInfo` returns home directory information only on servers, some second-guessing is applied. First, if the user name matches `%USERNAME%`, `%USERPROFILE%` is returned as is. Second, if the user name is different, but `dirname(%USERPROFILE)\\%USERNAME%` exists and is a directory, it is returned as the best informed guess. Otherwise (or if libwusers is compiled with `_WUSER_NO_HEURISTICS`), and empty string is returned.
* The second guess for `pw_shell` is the value of `%ComSpec%`.
* The _account_ expiration time is returned as `pw_expire`.
* There is no corresponding field for `pw_change` (requred password change time). Therefore `pw_expire` is returned if the password has _not_ expired. If it has, the current time minus 86400 seconds (i.e. same time yesterday) is returned.

### Group information

_*** Groups are WIP! ***_

Group field translation logic is much more straightforward. `gr_name` is the group name, `gr_mem` is a null-terminated `char*` array initialized from [GROUP_USER_INFO_0](https://learn.microsoft.com/en-us/windows/desktop/api/lmaccess/ns-lmaccess-group_users_info_0) values, `gr_gid` is the RID. `gr_passwd` has no Windows equivalent; an asterisk (`*`) is returned.

## Memory ownership

Memory ownership by `libwusers` is exactly as documented in the respective OpenBSD manual pages: the library owns
* the last (translated) entry returned by non-reentrant APIs, together with its string data;
* the last batch of (untranslated) entries being iterated over with `*ent` API;
* (as a courtesy) the last few hundred solitary user names and stringified UIDs.

The only difference is that `stayopen` in `setpassent` has no Windows equivalent (there are no files being kept "open",
at least on the surface) and is therefore disrespected.

Some of the memory management logic relies on the fact that `pw_shell` (the last `char*` field) is also the last field processed by `pw_dup()`.
If you want to change that, search for `reinterpret_cast<char*>` to highlight these places in the code.

Semantically constant C-string values (such as `*` in lieu of passwords, or privilege class names), though syntactically mutable, MAY reside in read-only memory.

# Terms and conditions

## License

`libwusers` is free as in freedom. `struct passwd` and `struct group` definitions, as well as POSIX and BSD API function prototypes,
thin as they are, have been reused from [OpenBSD source code](https://github.com/openbsd/src/tree/master/include) available under the
[3-clause BSD license](https://www.openbsd.org/policy.html). Everything contributed on top of that — particularly, but not limited to,
executable code, algorithms and documentation — is released into the public domain (where it rightfully belongs)
with a no-strings-attached [CC0 license](LICENSE).

## Support

All bets are off. This project is being worked on in our spare time to support another project being worked on in our spare time.
There is no guarantee that someone would even _respond_ in a timely fashion; but nevertheless, feel free and invited to drop a note,
report a bug, suggest a feature or contribute a change. After all, you are a techie, right? `libwusers` is of no use to you unless you are.

## Code of conduct

Um… Let's put it this way: don't do things you would be escorted out of a coffee shop for. That is, don't do them _here_.
