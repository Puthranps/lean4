/*
Copyright (c) 2026 Puthranps. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Puthranps
*/
#pragma once
#include <windows.h>
#include <cstdint>

// Trusted-controller interface for a blocking native launch experiment.
struct sandbox_request {
    const wchar_t * command;
    const wchar_t * const * arguments;
    uint32_t argument_count;
    const wchar_t * cwd;
    const wchar_t * const * readable_paths;
    uint32_t readable_count;
    const wchar_t * const * writable_paths;
    uint32_t writable_count;
    const wchar_t * const * environment;
    uint32_t environment_count;
    int network;
};

// Return a Windows setup/cleanup error separately from the child's exit code.
extern "C" __declspec(dllexport) DWORD sandbox_run(
    const sandbox_request * request, DWORD * child_exit,
    wchar_t * error, uint32_t error_capacity);
