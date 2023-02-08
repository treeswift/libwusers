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
#include <lm.h>       // NetApiBufferFree (MOREINFO separate by functionality?)

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

struct FreeNetBuffer {
    void operator()(BYTE* ptr) { if(ptr) NetApiBufferFree(ptr); }
};

const char* IDToA(OutBinder& out_str, unsigned int id, bool no = false);

void GC(OutBinder& bdr); // trim oldies that probably aren't goldies

unsigned int GetRID(PSID sid);

template<typename POSIX_RECORD_T> POSIX_RECORD_T* PointerTo(POSIX_RECORD_T& rec) { return &rec; }
template<typename POSIX_RECORD_T> POSIX_RECORD_T* NotFound() { return nullptr; }

template<typename POSIX_RECORD_T> struct IA;

template<typename POSIX_RECORD_T, typename NETAPI_INFO_T>
bool FillFrom(POSIX_RECORD_T& out, const NETAPI_INFO_T& wu_infoX, const OutWriter& writer);

template<typename POSIX_RECORD_T, typename NETAPI_INFO_T, int LVL,
        NET_API_STATUS (*GetInfo)(LPCWSTR, LPCWSTR, DWORD, LPBYTE*),
        NET_API_STATUS StatusNotFound>
POSIX_RECORD_T* QueryInfoByName(const std::wstring& name, POSIX_RECORD_T* out_ptr, const OutWriter& writer) {
    POSIX_RECORD_T * retval = nullptr;
    NETAPI_INFO_T * wu_infoX = nullptr;
    switch((*GetInfo)(nullptr, name.c_str(), LVL, reinterpret_cast<unsigned char**>(&wu_infoX))) {
    case ERROR_ACCESS_DENIED:
        set_last_error(EACCES);
        break;
    case ERROR_BAD_NETPATH: // can't happen -- we are local
    case NERR_InvalidComputer: // ^^ ditto
        set_last_error(EHOSTUNREACH);
        break;
    case StatusNotFound:
        set_last_error(ENOENT);
        break;
    case NERR_Success:
        retval = out_ptr;
        FillFrom(*retval, *wu_infoX, writer);
        break;
    default:
        set_last_error(EIO);
    }
    if(wu_infoX) {
        NetApiBufferFree(wu_infoX);
    }
    // BinderWriter can't fail with ERANGE (but BufferWriter can)
    return retval;
}

template<typename NETAPI_INFO_T, int LVL,
        NET_API_STATUS (*Enumerate)(LPCWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, PDWORD_PTR)>
struct EnumQueryState {
    // set large enough to fit in a single query on a workstation
    // but small enough to avoid hoarding too much memory.
    // MAX_PREFERRED_LENGTH will request as much memory as needed
    // to finish enumeration in one pass even on a server.
    static constexpr const std::size_t PAGE = 32768u;

    std::unique_ptr<BYTE, FreeNetBuffer> buf;
    std::size_t offset;
    std::size_t cursor;
    DWORD entries_full;
    DWORD entries_read;
    DWORD query_resume;

    const NETAPI_INFO_T* buffer() const { return reinterpret_cast<const NETAPI_INFO_T*>(buf.get()); }

    void reset() {
        buf.reset();
        offset = 0u;
        entries_read = 0u;
        entries_full = 0u;
        query_resume = 0u;
    }

    void query() {
        set_last_error(0);
        LPBYTE optr;
        auto page = PAGE;
        do switch((*Enumerate)(nullptr, LVL, &optr, page, &entries_read, &entries_full, &query_resume)) {
        case ERROR_ACCESS_DENIED:
            set_last_error(EACCES);
            return;
        case ERROR_INVALID_LEVEL:
            set_last_error(EINVAL);
            return;
        case NERR_InvalidComputer:
            set_last_error(EHOSTUNREACH);
            return;
        case ERROR_MORE_DATA:
        case NERR_Success:
            buf.reset(optr);
            offset += cursor;
            cursor = 0u;
            return;
        case NERR_BufTooSmall:
            page <<= 1;
            break;
        default:
            set_last_error(EIO);
            return;
        } while(!errno);
    }

    const NETAPI_INFO_T* curr() const {
        return &buffer()[cursor];
    }

    const NETAPI_INFO_T* step() {
        if(buf.get()) {
            if(cursor >= entries_read) {
                if(cursor + offset >= entries_full) {
                    return nullptr;
                } else {
                    query();
                }
            }
            return &buffer()[cursor++];
        } else {
            return nullptr;
        }
    }
};

template<typename POSIX_RECORD_T>
struct Stateless {
    using IA = IA<POSIX_RECORD_T>;
    using NETAPI_INFO_T = typename IA::NETAPI_INFO_T;

    static POSIX_RECORD_T* QueryByName(const std::wstring& name, POSIX_RECORD_T* out_ptr, const OutWriter& writer) {
        return QueryInfoByName<POSIX_RECORD_T, NETAPI_INFO_T, IA::LVL, &IA::GetInfo, IA::NotFound>(name, out_ptr, writer);
    }
};

template<typename POSIX_RECORD_T>
struct State : public Stateless<POSIX_RECORD_T> {
    using IA = IA<POSIX_RECORD_T>;
    using id_t  = typename IA::id_t;
    using NETAPI_INFO_T = typename IA::NETAPI_INFO_T;
    using QueryState = EnumQueryState<NETAPI_INFO_T, IA::LVL, &IA::Enumerate>;

    POSIX_RECORD_T owned_record;
    OutBinder owned_binder;
    QueryState query_state;

    POSIX_RECORD_T* queryByName(const std::wstring& name) {
        return this->QueryByName(name, &owned_record, BinderWriter(owned_binder = {}));
    }

    POSIX_RECORD_T* fillInternalEntry(const NETAPI_INFO_T* wu_info) {
        return (wu_info && FillFrom(owned_record, *wu_info, BinderWriter(owned_binder = {}))) ? &owned_record : nullptr;
    }

    POSIX_RECORD_T* nextEntry() {
        return fillInternalEntry(query_state.step());
    }

    // note that we could extract the condition predicate as well; but there is no POSIX API to request a generic query
    template<typename R>
    R queryByIdAndMap(id_t id, std::function<R(POSIX_RECORD_T&)> report_asis,
                            std::function<R(const NETAPI_INFO_T*)> process,
                            std::function<R()> not_found) {
        // let's examine our caches first
        if(IA::IdOf(owned_record) == id) { // lucky!
            return report_asis(owned_record);
        }
        if(query_state.buffer() && query_state.entries_read) {
            for(std::size_t i = 0; i < query_state.entries_read; ++i) {
                const NETAPI_INFO_T * candidate = query_state.buffer()+i;
                if(IA::IdOf(candidate) == id) { // lucky too
                    return process(candidate);
                }
            }
        }
        // bummer. run a full query, albeit without touching state.
        // we could pull the remainder of this method into Stateless
        // but let's keep the logic in one place (+encourage caching)
        QueryState local_query;
        local_query.reset();
        local_query.query();
        const NETAPI_INFO_T * candidate = nullptr;
        while((candidate = local_query.step())) {
            if(IA::IdOf(candidate) == id) {
                return process(candidate);
            }
        }
        return not_found();
    }

    POSIX_RECORD_T* queryById(id_t id) {
        return queryByIdAndMap<POSIX_RECORD_T*>(id,
            &PointerTo<POSIX_RECORD_T>,
            // the following could be `std::bind` but I had issues with it before
            [this](const NETAPI_INFO_T* info) { return fillInternalEntry(info); },
            &NotFound<POSIX_RECORD_T>);
    }

    // utter damn sugar, but let's keep final specializations as thin as possible

    POSIX_RECORD_T* queryByName(const char* name) {
        set_last_error(0);
        const std::wstring wname = to_win_str(name);
        return wname.empty()
            ? nullptr // sets EINVAL
            : queryByName(wname);
    }

    void beginEnum() {
        query_state.reset();
        query_state.query();
    }

    void endEnum() {
        query_state.reset();
    }

    const char* idToName(id_t id, bool nouser) {
        GC(owned_binder);
        return queryByIdAndMap<const char*>(id, &IA::NameOf,
            [&](const NETAPI_INFO_T* wu_info) {
                return BinderWriter(owned_binder)(IA::WNameOf(wu_info));
            },
            [&]() { return IDToA(owned_binder, id, nouser); }
        );
    }

    int nameToId(const char* name, id_t* out_id) {
        if(!name) {
            set_last_error(EINVAL);
            return -1;
        }
        if((owned_binder.size() && IA::NameOf(owned_record) && !std::strcmp(IA::NameOf(owned_record), name))
            || queryByName(name) /* modifies owned_record used in the next line */) {
            *out_id = IA::IdOf(owned_record);
            return 0;
        }
        return -1;
    }
};

}

#endif /* !_CHR_H_ */
