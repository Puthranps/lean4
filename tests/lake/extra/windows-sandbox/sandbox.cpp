/*
Copyright (c) 2026 Puthranps. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Puthranps
*/
#include "sandbox.h"
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
namespace fs = std::filesystem;

void trace(const wchar_t * phase) {
    wchar_t enabled[2];
    if (GetEnvironmentVariableW(L"LEAN_SANDBOX_DEBUG", enabled, 2)) {
        std::fwprintf(stderr, L"sandbox: %ls\n", phase);
        std::fflush(stderr);
    }
}

struct failure : std::exception {
    DWORD code;
    std::wstring message;
    failure(DWORD value, std::wstring text) : code(value), message(std::move(text)) {}
};

void require(bool condition, const wchar_t * operation) {
    if (!condition) throw failure(GetLastError(), operation);
}

void check(DWORD code, const wchar_t * operation) {
    if (code != ERROR_SUCCESS) throw failure(code, operation);
}

class handle {
    HANDLE value = nullptr;
public:
    handle() = default;
    explicit handle(HANDLE item) : value(item) {}
    handle(const handle &) = delete;
    handle & operator=(const handle &) = delete;
    ~handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    HANDLE get() const { return value; }
    void reset(HANDLE item) {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
        value = item;
    }
};

struct local_delete { void operator()(void * pointer) const { if (pointer) LocalFree(pointer); } };
using local_memory = std::unique_ptr<void, local_delete>;

class acl_lock {
    handle mutex;
public:
    acl_lock() : mutex(CreateMutexW(nullptr, FALSE, L"Local\\LeanSandboxPrototypeAcl")) {
        require(mutex.get() != nullptr, L"CreateMutexW");
        DWORD result = WaitForSingleObject(mutex.get(), INFINITE);
        require(result == WAIT_OBJECT_0 || result == WAIT_ABANDONED, L"wait for ACL mutex");
    }
    ~acl_lock() { ReleaseMutex(mutex.get()); }
};

void change_access(const fs::path & path, PSID sid, ACCESS_MODE mode, DWORD permissions) {
    acl_lock lock;
    PACL old_acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    check(GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
          nullptr, nullptr, &old_acl, nullptr, &descriptor), L"read directory DACL");
    local_memory old_descriptor(descriptor);
    EXPLICIT_ACCESSW entry{};
    entry.grfAccessPermissions = permissions;
    entry.grfAccessMode = mode;
    entry.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    BuildTrusteeWithSidW(&entry.Trustee, sid);
    PACL new_acl = nullptr;
    check(SetEntriesInAclW(1, &entry, old_acl, &new_acl), L"construct directory DACL");
    local_memory new_descriptor(new_acl);
    auto name = path.wstring();
    check(SetNamedSecurityInfoW(name.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
          nullptr, nullptr, new_acl, nullptr), L"set directory DACL");
}

void validate_entry(const fs::path & path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    require(attributes != INVALID_FILE_ATTRIBUTES, L"inspect grant path");
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
        throw failure(ERROR_NOT_SUPPORTED, L"prototype rejects reparse points in granted trees");
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        handle file(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        require(file.get() != INVALID_HANDLE_VALUE, L"inspect file aliases");
        BY_HANDLE_FILE_INFORMATION information{};
        require(GetFileInformationByHandle(file.get(), &information) != FALSE, L"inspect hard links");
        if (information.nNumberOfLinks != 1)
            throw failure(ERROR_NOT_SUPPORTED, L"prototype rejects hard links in granted trees");
    }
}

fs::path validate_tree(const wchar_t * input) {
    fs::path path(input);
    if (!path.is_absolute() || path == path.root_path())
        throw failure(ERROR_INVALID_PARAMETER, L"grants must name absolute non-root paths");
    validate_entry(path);
    path = fs::canonical(path);
    if (fs::is_directory(path))
        for (const auto & entry : fs::recursive_directory_iterator(path)) validate_entry(entry.path());
    return path;
}

struct label_change {
    fs::path path;
    local_memory descriptor;
    PACL old_label;
};

class session {
    std::wstring name;
    PSID sid = nullptr;
    std::vector<fs::path> grants;
    std::vector<label_change> labels;
public:
    void create() {
        GUID guid{};
        HRESULT result = CoCreateGuid(&guid);
        if (FAILED(result)) throw failure(static_cast<DWORD>(result), L"CoCreateGuid");
        wchar_t text[40]{};
        require(StringFromGUID2(guid, text, 40) != 0, L"format sandbox identity");
        name = L"LeanProbe." + std::to_wstring(GetCurrentProcessId()) + L"." + std::wstring(text + 1, 36);
        result = CreateAppContainerProfile(name.c_str(), L"Lean sandbox prototype",
                   L"Disposable native sandbox experiment", nullptr, 0, &sid);
        if (FAILED(result)) throw failure(static_cast<DWORD>(result), L"CreateAppContainerProfile");
    }
    PSID identity() const { return sid; }

    void grant(const wchar_t * input, bool writable) {
        auto path = validate_tree(input);
        DWORD permissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        if (writable) permissions |= FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
        grants.push_back(path);
        // Track the root before propagation, including a partially failed update.
        change_access(path, sid, SET_ACCESS, permissions);
        if (writable) {
            PSECURITY_DESCRIPTOR old_descriptor = nullptr;
            PACL old_label = nullptr;
            check(GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                  nullptr, nullptr, nullptr, &old_label, &old_descriptor), L"read directory integrity label");
            labels.push_back({path, local_memory(old_descriptor), old_label});
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"S:(ML;OICI;NW;;;LW)", SDDL_REVISION_1, &descriptor, nullptr) != FALSE,
                L"construct low integrity label");
            local_memory memory(descriptor);
            BOOL present = FALSE, inherited = FALSE;
            PACL label = nullptr;
            require(GetSecurityDescriptorSacl(descriptor, &present, &label, &inherited) != FALSE,
                    L"read low integrity label");
            auto text = path.wstring();
            check(SetNamedSecurityInfoW(text.data(), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                  nullptr, nullptr, nullptr, label), L"set writable directory integrity label");
        }
    }

    std::wstring cleanup() noexcept {
        std::wstring errors;
        for (auto i = labels.rbegin(); i != labels.rend(); ++i) {
            auto text = i->path.wstring();
            DWORD code = SetNamedSecurityInfoW(text.data(), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                         nullptr, nullptr, nullptr, i->old_label);
            if (code) errors += L"restore integrity label: " + std::to_wstring(code) + L"; ";
        }
        labels.clear();
        for (auto i = grants.rbegin(); i != grants.rend(); ++i) {
            try { change_access(*i, sid, REVOKE_ACCESS, 0); }
            catch (const failure & error) { errors += error.message + L": " + std::to_wstring(error.code) + L"; "; }
            catch (...) { errors += L"unexpected grant cleanup failure; "; }
        }
        grants.clear();
        if (sid) {
            HRESULT result = DeleteAppContainerProfile(name.c_str());
            if (FAILED(result)) errors += L"DeleteAppContainerProfile: " + std::to_wstring(result) + L"; ";
            FreeSid(sid);
            sid = nullptr;
        }
        return errors;
    }
    ~session() { cleanup(); }
};

std::wstring quote(const std::wstring & input) {
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t character : input) {
        if (character == L'\\') { ++slashes; continue; }
        if (character == L'\"') result.append(slashes * 2 + 1, L'\\');
        else result.append(slashes, L'\\');
        slashes = 0;
        result += character;
    }
    result.append(slashes * 2, L'\\');
    return result + L'\"';
}

class attributes {
    std::vector<unsigned char> storage;
    LPPROC_THREAD_ATTRIBUTE_LIST list;
public:
    explicit attributes(DWORD count) {
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, count, 0, &bytes);
        storage.resize(bytes);
        list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        require(InitializeProcThreadAttributeList(list, count, 0, &bytes) != FALSE,
                L"InitializeProcThreadAttributeList");
    }
    ~attributes() { DeleteProcThreadAttributeList(list); }
    LPPROC_THREAD_ATTRIBUTE_LIST get() { return list; }
    void set(DWORD_PTR attribute, void * value, SIZE_T bytes) {
        require(UpdateProcThreadAttribute(list, 0, attribute, value, bytes, nullptr, nullptr) != FALSE,
                L"UpdateProcThreadAttribute");
    }
};

class job {
    handle object;
public:
    job() : object(CreateJobObjectW(nullptr, nullptr)) {
        require(object.get() != nullptr, L"CreateJobObjectW");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        require(SetInformationJobObject(object.get(), JobObjectExtendedLimitInformation,
                    &limits, sizeof(limits)) != FALSE, L"set job kill-on-close policy");
    }
    HANDLE get() { return object.get(); }
    bool stop() noexcept {
        if (!TerminateJobObject(object.get(), 1)) return false;
        for (unsigned i = 0; i < 500; ++i) {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information{};
            if (!QueryInformationJobObject(object.get(), JobObjectBasicAccountingInformation,
                 &information, sizeof(information), nullptr)) return false;
            if (information.ActiveProcesses == 0) return true;
            Sleep(10);
        }
        return false;
    }
    ~job() { stop(); }
};

DWORD launch(const sandbox_request & request, PSID sid) {
    job processes;
    SECURITY_CAPABILITIES security{};
    security.AppContainerSid = sid;
    BYTE network_sid[SECURITY_MAX_SID_SIZE];
    SID_AND_ATTRIBUTES capability{};
    if (request.network) {
        DWORD bytes = sizeof(network_sid);
        require(CreateWellKnownSid(WinCapabilityInternetClientSid, nullptr, network_sid, &bytes) != FALSE,
                L"create network capability");
        capability.Sid = network_sid;
        capability.Attributes = SE_GROUP_ENABLED;
        security.Capabilities = &capability;
        security.CapabilityCount = 1;
    }
    handle input, output, errors;
    HANDLE inherited[3]{};
    handle * holders[] = {&input, &output, &errors};
    DWORD kinds[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    handle null_input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr, OPEN_EXISTING, 0, nullptr));
    require(null_input.get() != INVALID_HANDLE_VALUE, L"open null input");
    for (int i = 0; i < 3; ++i) {
        HANDLE original = i == 0 ? null_input.get() : GetStdHandle(kinds[i]);
        HANDLE duplicate = nullptr;
        require(DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(), &duplicate,
                    0, TRUE, DUPLICATE_SAME_ACCESS) != FALSE, L"duplicate standard handle");
        holders[i]->reset(duplicate);
        inherited[i] = duplicate;
    }
    attributes attributes(3);
    attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security, sizeof(security));
    attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited));
    HANDLE job_handle = processes.get();
    // Attach at creation, so a controller crash cannot strand a pre-assignment child.
    attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handle, sizeof(job_handle));
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited[0];
    startup.StartupInfo.hStdOutput = inherited[1];
    startup.StartupInfo.hStdError = inherited[2];
    startup.lpAttributeList = attributes.get();
    std::wstring command_line = quote(request.command);
    for (uint32_t i = 0; i < request.argument_count; ++i)
        command_line += L" " + quote(request.arguments[i]);
    std::vector<std::wstring> entries;
    for (uint32_t i = 0; i < request.environment_count; ++i) entries.emplace_back(request.environment[i]);
    std::sort(entries.begin(), entries.end(), [](const auto & first, const auto & second) {
        return CompareStringOrdinal(first.c_str(), -1, second.c_str(), -1, TRUE) == CSTR_LESS_THAN;
    });
    std::vector<wchar_t> environment;
    for (const auto & entry : entries) {
        environment.insert(environment.end(), entry.begin(), entry.end());
        environment.push_back(0);
    }
    environment.push_back(0);
    if (entries.empty()) environment.push_back(0);
    PROCESS_INFORMATION information{};
    require(CreateProcessW(request.command, command_line.data(), nullptr, nullptr, TRUE,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environment.data(), request.cwd, &startup.StartupInfo, &information) != FALSE,
                L"CreateProcessW(AppContainer)");
    handle process(information.hProcess), thread(information.hThread);
    require(WaitForSingleObject(process.get(), INFINITE) == WAIT_OBJECT_0, L"wait for sandbox child");
    DWORD exit_code = 0;
    require(GetExitCodeProcess(process.get(), &exit_code) != FALSE, L"read sandbox child status");
    if (!processes.stop()) throw failure(ERROR_TIMEOUT, L"terminate sandbox descendants");
    return exit_code;
}
}

DWORD sandbox_run(const sandbox_request * request, DWORD * child_exit,
                  wchar_t * error, uint32_t capacity) {
    if (!request || !child_exit || !error || !capacity) return ERROR_INVALID_PARAMETER;
    DWORD result = ERROR_SUCCESS;
    std::wstring message;
    session context;
    try {
        trace(L"create profile");
        context.create();
        trace(L"grant readable paths");
        for (uint32_t i = 0; i < request->readable_count; ++i) context.grant(request->readable_paths[i], false);
        for (uint32_t i = 0; i < request->writable_count; ++i) context.grant(request->writable_paths[i], true);
        trace(L"launch child");
        *child_exit = launch(*request, context.identity());
        trace(L"child finished");
    } catch (const failure & problem) {
        result = problem.code ? problem.code : ERROR_GEN_FAILURE;
        message = problem.message + L" (" + std::to_wstring(result) + L")";
    } catch (const std::exception & problem) {
        result = ERROR_GEN_FAILURE;
        std::string text = problem.what();
        message.assign(text.begin(), text.end());
    } catch (...) {
        result = ERROR_GEN_FAILURE;
        message = L"unknown native setup failure";
    }
    trace(L"cleanup");
    auto cleanup_errors = context.cleanup();
    if (!cleanup_errors.empty()) {
        result = ERROR_GEN_FAILURE;
        message += L"; cleanup: " + cleanup_errors;
    }
    wcsncpy_s(error, capacity, message.c_str(), _TRUNCATE);
    return result;
}
