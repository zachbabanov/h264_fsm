/*
* @license
* (C) zachbabanov
*
*/

#include <player.hpp>
#include <common.hpp>
#include <logger.hpp>

#include <cstring>
#include <vector>
#include <thread>
#include <deque>

#ifdef __linux__
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#else
#include <windows.h>
#endif

using namespace project::player;
using namespace project::common;
using namespace project::log;

/*
 * Implementation notes:
 * - On Linux we create a pipe, fork, set child stdin to read end and exec ffplay.
 * - Parent keeps write end and writes into it non-blocking.
 * - On Windows we create pipe, CreateProcess with inherited read end and spawn a writer thread that drains a queue.
 */

struct PlayerProcess::Impl {
#ifdef __linux__
    int write_fd; // write end of the pipe connected to child's stdin
    pid_t pid;
#else
    HANDLE child_stdin_wr; // parent write handle
    PROCESS_INFORMATION pi;
    std::thread writer_thread;
    std::mutex mtx;
    std::condition_variable cv;
    std::deque<std::vector<char>> queue;
    std::atomic<bool> running;
#endif
    Impl() :
#ifdef __linux__
      write_fd(-1), pid(-1)
#else
      child_stdin_wr(INVALID_HANDLE_VALUE)
#endif
    {}
};

PlayerProcess::PlayerProcess(): impl_(new Impl()) {}
PlayerProcess::~PlayerProcess() { stop(); delete impl_; }

/**
 * @brief Helper to build argv-like array for execvp.
 */
static std::vector<char*> build_argv(const std::string &cmd, const std::vector<std::string> &args) {
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(cmd.c_str()));
    for (auto &a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    return argv;
}

std::unique_ptr<PlayerProcess> PlayerProcess::launch(const std::string &player_cmd, const std::vector<std::string> &app_args) {
    auto p = std::unique_ptr<PlayerProcess>(new PlayerProcess());
#ifdef __linux__
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        LOG_PLAYER_INFO("Player: pipe creation failed");
        return nullptr;
    }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(pipefd[0]); close(pipefd[1]); LOG_PLAYER_INFO("Player: fork failed"); return nullptr; }
    if (pid == 0) {
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        std::vector<char*> argv;
        if (app_args.empty()) {
            // Default parameters for low-latency H.264 streaming from stdin
            argv = build_argv(player_cmd, {
                    "-fflags", "nobuffer",
                    "-flags", "low_delay",
                    "-framedrop",
                    "-strict", "experimental",
                    "-f", "h264",
                    "-i", "-",  // Read from stdin
                    "-window_title", "H.264 Stream Player"
            });
        } else {
            argv = build_argv(player_cmd, app_args);
        }

        // Execute the player
        execvp(player_cmd.c_str(), argv.data());
        perror("execvp player");
        _exit(1);
    } else {
        close(pipefd[0]);
        p->impl_->write_fd = pipefd[1];
        int flags = fcntl(p->impl_->write_fd, F_GETFL, 0);
        fcntl(p->impl_->write_fd, F_SETFL, flags | O_NONBLOCK);
        p->impl_->pid = pid;
        LOG_PLAYER_INFO("Player started: cmd='{}' pid={} write_fd={}", player_cmd, (int)pid, p->impl_->write_fd);
        return p;
    }
#else
    // Windows implementation (unchanged)
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE child_stdin_rd = NULL;
    HANDLE child_stdin_wr = NULL;
    if (!CreatePipe(&child_stdin_rd, &child_stdin_wr, &sa, 0)) {
        LOG_PLAYER_INFO("Player: CreatePipe failed");
        return nullptr;
    }
    SetHandleInformation(child_stdin_wr, HANDLE_FLAG_INHERIT, 0);

    // Build command line with arguments
    std::string cmdline = player_cmd;
    for (const auto& arg : app_args) {
        cmdline += " " + arg;
    }

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.hStdInput = child_stdin_rd;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags = STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessA(
        NULL,
        (LPSTR)cmdline.c_str(),
        NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi
    );
    if (!ok) {
        LOG_PLAYER_INFO("Player CreateProcess failed: cmd={}", cmdline.c_str());
        CloseHandle(child_stdin_rd);
        CloseHandle(child_stdin_wr);
        return nullptr;
    }
    CloseHandle(child_stdin_rd);
    p->impl_->child_stdin_wr = child_stdin_wr;
    p->impl_->pi = pi;
    p->impl_->running = true;

    p->impl_->writer_thread = std::thread([impl = p->impl_, cmdline]() {
        LOG_PLAYER_INFO("Player writer-thread started for cmd '{}'", cmdline.c_str());
        while (impl->running) {
            std::unique_lock<std::mutex> lk(impl->mtx);
            impl->cv.wait(lk, [&](){ return !impl->queue.empty() || !impl->running; });
            while (!impl->queue.empty()) {
                auto buf = std::move(impl->queue.front());
                impl->queue.pop_front();
                lk.unlock();
                DWORD written = 0;
                BOOL ok = WriteFile(impl->child_stdin_wr, buf.data(), (DWORD)buf.size(), &written, NULL);
                if (!ok) {
                    LOG_PLAYER_INFO("Player writer-thread WriteFile failed, exiting writer");
                    impl->running = false;
                    break;
                }
                if (written < buf.size()) {
                    LOG_PLAYER_INFO("Player writer-thread partial write: wrote={} expected={}", (uint32_t)written, (uint32_t)buf.size());
                }
                lk.lock();
            }
        }
        LOG_PLAYER_INFO("Player writer-thread exiting");
    });

    LOG_PLAYER_INFO("Player started (Windows): cmd='{}' pid={}", player_cmd, (unsigned long long)pi.dwProcessId);
    return p;
#endif
}

ssize_t PlayerProcess::write_data(const char *buf, size_t len) {
    if (!impl_) return -1;
#ifdef __linux__
    if (impl_->write_fd < 0) return -1;
    ssize_t n = ::write(impl_->write_fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            LOG_PLAYER_INFO("Player write would block write_fd={}", impl_->write_fd);
            return 0;
        }
        LOG_PLAYER_INFO("Player write error errno={}", errno);
        return -1;
    }
    return n;
#else
    if (impl_->child_stdin_wr == INVALID_HANDLE_VALUE) {
        LOG_PLAYER_INFO("Player write_data called but child handle invalid");
        return -1;
    }
    std::vector<char> v(buf, buf + len);
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        impl->queue.push_back(std::move(v));
    }
    impl->cv.notify_one();
    return (ssize_t)len; // we queued all
#endif
}

int PlayerProcess::get_write_fd() const {
#ifdef __linux__
    return impl_->write_fd;
#else
    return -1;
#endif
}

void PlayerProcess::stop() {
    if (!impl_) return;
#ifdef __linux__
    if (impl_->write_fd >= 0) {
        close(impl_->write_fd);
        LOG_PLAYER_INFO("Player write_fd closed {}", impl_->write_fd);
        impl_->write_fd = -1;
    }
    if (impl_->pid > 0) {
        kill(impl_->pid, SIGTERM);
        waitpid(impl_->pid, NULL, 0);
        LOG_PLAYER_INFO("Player process terminated pid={}", (int)impl_->pid);
        impl_->pid = -1;
    }
#else
    if (impl_->running) {
        impl_->running = false;
        impl_->cv.notify_all();
    }
    if (impl_->writer_thread.joinable()) {
        impl_->writer_thread.join();
        LOG_PLAYER_INFO("Player writer-thread joined");
    }
    if (impl_->child_stdin_wr != INVALID_HANDLE_VALUE) {
        CloseHandle(impl_->child_stdin_wr);
        LOG_PLAYER_INFO("Player handle closed");
        impl_->child_stdin_wr = INVALID_HANDLE_VALUE;
    }
    if (impl_->pi.hProcess) {
        TerminateProcess(impl_->pi.hProcess, 0);
        CloseHandle(impl_->pi.hProcess);
        CloseHandle(impl_->pi.hThread);
        LOG_PLAYER_INFO("Player process terminated");
        impl_->pi = {};
    }
#endif
}
