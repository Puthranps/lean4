/*
Copyright (c) 2026 Puthranps. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Puthranps
*/
#include "sandbox.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {
using namespace winrt::Windows::Data::Json;

std::wstring string(const IJsonValue & value) {
    auto text = value.GetString();
    std::wstring result(text.c_str(), text.size());
    if (result.find(L'\0') != std::wstring::npos)
        throw std::runtime_error("request strings must not contain NUL");
    return result;
}

std::vector<std::wstring> strings(const JsonArray & array) {
    std::vector<std::wstring> result;
    for (auto value : array) result.push_back(string(value));
    return result;
}

std::vector<const wchar_t *> pointers(const std::vector<std::wstring> & strings) {
    std::vector<const wchar_t *> result;
    for (const auto & string : strings) result.push_back(string.c_str());
    return result;
}
}

// A standalone trusted caller for the library, not a proposed production helper.
int wmain(int argc, wchar_t ** argv) {
    if (argc != 2) { std::cerr << "expected a trusted JSON request path\n"; return 2; }
    try {
        winrt::init_apartment();
        std::ifstream file{std::filesystem::path(argv[1])};
        if (!file) throw std::runtime_error("cannot read request");
        std::string contents{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
        auto data = JsonObject::Parse(winrt::to_hstring(contents));
        auto command = string(data.GetNamedValue(L"cmd"));
        auto cwd = string(data.GetNamedValue(L"cwd"));
        auto arguments = strings(data.GetNamedArray(L"args"));
        auto readable = strings(data.GetNamedArray(L"readablePaths"));
        auto writable = strings(data.GetNamedArray(L"writablePaths"));
        std::vector<std::wstring> environment;
        for (auto value : data.GetNamedArray(L"env")) {
            auto pair = value.GetArray();
            if (pair.Size() != 2) throw std::runtime_error("invalid environment pair");
            auto key = string(pair.GetAt(0));
            if (key.empty() || key.find(L'=') != std::wstring::npos)
                throw std::runtime_error("invalid environment variable name");
            environment.push_back(key + L"=" + string(pair.GetAt(1)));
        }
        auto argument_pointers = pointers(arguments), read_pointers = pointers(readable);
        auto write_pointers = pointers(writable), environment_pointers = pointers(environment);
        sandbox_request request{
            command.c_str(), argument_pointers.data(), static_cast<uint32_t>(arguments.size()),
            cwd.c_str(), read_pointers.data(), static_cast<uint32_t>(readable.size()),
            write_pointers.data(), static_cast<uint32_t>(writable.size()),
            environment_pointers.data(), static_cast<uint32_t>(environment.size()),
            data.GetNamedBoolean(L"network") ? 1 : 0
        };
        DWORD exit_code = 0;
        wchar_t error[4096]{};
        DWORD status = sandbox_run(&request, &exit_code, error, 4096);
        if (status) { std::wcerr << L"sandbox setup/cleanup failed: " << error << L'\n'; return 2; }
        return static_cast<int>(exit_code);
    } catch (const winrt::hresult_error & error) {
        std::wcerr << error.message().c_str() << L'\n';
    } catch (const std::exception & error) {
        std::cerr << error.what() << '\n';
    }
    return 2;
}
