// Behavioral probe shared by the Linux baseline and the Windows prototype.
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// Exit 10 means the requested operation failed. Other failures are test errors.
int main(int argc, char ** argv) {
    if (argc < 2) return 2;
    std::string op = argv[1];
    if (op == "read" && argc == 3) {
        std::ifstream file(argv[2]);
        std::string value;
        return std::getline(file, value) ? 0 : 10;
    }
    if (op == "write" && argc == 3) {
        std::ofstream file(argv[2]);
        file << "modified";
        file.close();
        return file ? 0 : 10;
    }
    if (op == "env" && argc == 4) {
#ifdef _WIN32
        char * value = nullptr;
        size_t length = 0;
        if (_dupenv_s(&value, &length, argv[2])) return 2;
        std::string actual = value ? value : "<absent>";
        std::free(value);
        return actual == argv[3] ? 0 : 11;
#else
        const char * value = std::getenv(argv[2]);
        return (value ? value : "<absent>") == std::string(argv[3]) ? 0 : 11;
#endif
    }
    if (op == "args") {
        for (int i = 2; i < argc; ++i) std::cout << argv[i] << '\n';
        return 0;
    }
    if (op == "linger" && argc == 3) {
#ifdef _WIN32
        unsigned long pid = GetCurrentProcessId();
#else
        unsigned long pid = getpid();
#endif
        std::ofstream file(argv[2]);
        file << pid;
        file.close();
        if (!file) return 2;
        for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (op == "alive" && argc == 3) {
#ifdef _WIN32
        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, std::stoul(argv[2]));
        if (!process) return 10;
        DWORD status = WaitForSingleObject(process, 0);
        CloseHandle(process);
        return status == WAIT_TIMEOUT ? 0 : 10;
#else
        std::ifstream status("/proc/" + std::string(argv[2]) + "/stat");
        std::string line;
        if (std::getline(status, line)) {
            auto end = line.find_last_of(')');
            if (end != std::string::npos && end + 2 < line.size() &&
                (line[end + 2] == 'Z' || line[end + 2] == 'X')) return 10;
        }
        return kill(std::stoul(argv[2]), 0) == 0 ? 0 : 10;
#endif
    }
    if (op == "spawn-write" && argc == 3) {
#ifdef _WIN32
        const char * childArgs[] = {argv[0], "write", argv[2], nullptr};
        auto code = _spawnv(_P_WAIT, argv[0], childArgs);
        return code == -1 ? 2 : static_cast<int>(code);
#else
        pid_t pid = fork();
        if (pid == -1) return 2;
        if (pid == 0) { execl(argv[0], argv[0], "write", argv[2], nullptr); _exit(2); }
        int status;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return 2;
        return WEXITSTATUS(status);
#endif
    }
    if (op == "network" && argc == 4) {
#ifdef _WIN32
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
        SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd == INVALID_SOCKET) return 10;
        DWORD timeout = 3000;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char *>(&timeout), sizeof(timeout));
#else
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return 10;
        timeval timeout{3, 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<unsigned short>(std::stoul(argv[3])));
        if (inet_pton(AF_INET, argv[2], &address.sin_addr) != 1) return 2;
        int result = connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
#ifdef _WIN32
        closesocket(fd);
        WSACleanup();
#else
        close(fd);
#endif
        return result == 0 ? 0 : 10;
    }
    return 2;
}
