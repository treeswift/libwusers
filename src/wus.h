/**
 * This file has no copyright assigned and is placed in the public domain.
 * This file is part of the libwusers compatibility library:
 *   https://github.com/treeswift/libwusers
 * No warranty is given; refer to the LICENSE file in the project root.
 */

#ifndef _CHR_H_
#define _CHR_H_

#include <list>
#include <memory>
#include <string>

#include <windows.h> // SID -> sid.h, sid.cpp

namespace wusers_impl {

unsigned int get_cp();

void set_last_error(int last_error);

// conversion functions set EINVAL if input is empty or conversion fails
std::wstring to_win_str(const char* posix_str, bool einval_if_empty = true);

std::wstring to_win_str(const std::string& posix_str, bool einval_if_empty = true);

using OutBinder = std::list<std::string>;

struct OutWriter
{
    // convert a null-terminated wide string
    virtual char* operator()(const wchar_t* wstr) const = 0;

    // store a chunk of data verbatim
    virtual char* operator()(const void* buf, std::size_t len) const = 0;

    // default constructor (for sub-smart compilers)
    OutWriter() = default;

    // enforce passing by ptr/reference:
    OutWriter(const OutWriter&) = delete;
    OutWriter& operator=(const OutWriter&) = delete;

    // allow pinning with smart pointers:
    virtual ~OutWriter() = default;
};

// "reentrant" (blahblah_r()) conversions into client-provided memory
class BufferWriter : public OutWriter {
public:
    BufferWriter(char*& buf, size_t& len) // no std:: to match C API!
        : out_buf(buf), buf_len(len) {}

    char* operator()(const wchar_t* wstr) const override;
    char* operator()(const void* buf, std::size_t len) const override;

private:
    char * &out_buf;
    size_t &buf_len;
};

// conversions into library-owned memory
class BinderWriter : public OutWriter {
public:
    BinderWriter(OutBinder& bdr) : out_bdr(bdr) {}
    
    char* operator()(const wchar_t* wstr) const override;
    char* operator()(const void* buf, std::size_t len) const override;

private:
    OutBinder& out_bdr;
};

std::wstring ExpandEnvvars(const wchar_t * percent_str);

const char* IDToA(OutBinder& out_str, unsigned int id, int no = 0);

unsigned int GetRID(PSID sid);

}

#endif /* !_CHR_H_ */
