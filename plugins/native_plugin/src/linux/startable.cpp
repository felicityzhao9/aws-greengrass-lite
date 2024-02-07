
#include "startable.hpp"

#include "abstract_process.hpp"
#include "linux/file_descriptor.hpp"
#include "pipe.hpp"
#include "process.hpp"
#include "rlimits.hpp"
#include "syscall.hpp"

#include <memory>
#include <string_view>
#include <system_error>

#include <csignal>
#include <sys/socket.h>
#include <unistd.h>

namespace ipc {

    inline constexpr auto defaultBufferSize = 0x0FFF;

    std::unique_ptr<Process> Startable::start(
        std::string_view command, util::Span<char *> argv, util::Span<char *> envp) const {

        // prepare to capture child process output
        Pipe outPipe{};
        Pipe errPipe{};

        // Prepare to alter user permissions
        UserInfo user{};
        // uid setting only works as root or with root-like permissions
        // TODO: investigate. Probably need a root setuid daemon...
        // or just ignore this step
        if(getgid() == 0 && getuid() == 0) {
            if(_user.has_value()) {
                if(_group.has_value()) {
                    getUserInfo(*_user, *_group);
                } else {
                    getUserInfo(*_user);
                }
            }
        }

        // Note: all memory allocation for the child process must be performed before forking
        auto pid = fork();
        switch(pid) {
            // parent, on error
            case -1:
                throw std::system_error(errno, std::generic_category());

            // child, runs process
            case 0: {
                // At this point, child should be extremely careful which APIs they call;
                // async-signal-safe to be safest

                // child process may be using select, which requires fds <= 1024
                resetFdLimit();

                // create a session so all decendants are reaped when SIGKILL/SIGTERM is received
                std::ignore = setsid();

                // pipe program output to parent process
                outPipe.input().duplicate(STDOUT_FILENO);
                errPipe.input().duplicate(STDERR_FILENO);
                std::ignore = outPipe.input().release();
                std::ignore = errPipe.input().release();
                outPipe.output().close();
                errPipe.output().close();

                setUserInfo(user);

                if(_workingDir.has_value()) {
                    if(chdir(_workingDir->c_str()) == -1) {
                        perror("chdir");
                    }
                }

                std::ignore = execvpe(_command.c_str(), argv.data(), envp.data());
                // only reachable if exec fails
                perror("execvpe");
                // SECURITY-TODO: log permissions error
                if(errno == EPERM || errno == EACCES) {
                }
                std::abort();
            }

            // parent process, PID is child process
            default: {
                FileDescriptor pidfd{pidfd_open(pid, 0)};
                // Most likely: out of file descriptors
                if(!pidfd) {
                    perror("pidfd_open");
                    auto err = std::error_code{errno, std::generic_category()};
                    std::ignore = kill(pid, SIGKILL);
                    throw std::system_error(err);
                }
                auto process = std::make_unique<Process>();
                process->setPidFd(std::move(pidfd))
                    .setOut(std::move(outPipe.output()))
                    .setErr(std::move(errPipe.output()))
                    .setCompletionHandler(_completeHandler.value_or([](auto &&...) {}))
                    .setErrHandler(_errHandler.value_or([](auto &&...) {}))
                    .setOutHandler(_outHandler.value_or([](auto &&...) {}));
                return process;
            }
        }
    }

} // namespace ipc
