#pragma once

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

EXPORT int ggapiMainThread(int argc, char *argv[], char *envp[]) noexcept;
