#include "plugin_loader.h"
#include "../tasks/task.h"

namespace fs = std::filesystem;

plugin::NativePlugin::~NativePlugin() {
#if defined(USE_DLFCN)
    if (_handle) {
        ::dlclose(_handle);
        _handle = nullptr;
    }
#elif defined(USE_WINDLL)
    if (_handle) {
        ::FreeLibrary(_handle);
        _handle = nullptr;
    }
#endif
}

void plugin::NativePlugin::load(const std::string & filePath) {
#if defined(USE_DLFCN)
    nativeHandle_t handle = ::dlopen(filePath.c_str(), RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
    _handle = handle;
    if (handle == nullptr) {
        std::string error {dlerror()};
        throw std::runtime_error(std::string("Cannot load shared object: ")+filePath + std::string(" ") + error);
    }
    _lifecycleFn = reinterpret_cast<lifecycleFn_t>(::dlsym(_handle, "greengrass_lifecycle"));
#elif defined(USE_WINDLL)
    nativeHandle_t handle = ::LoadLibraryEx(filePath.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    _handle = handle;
    if (handle == nullptr) {
        uint32_t lastError = ::GetLastError();
        // TODO: use FormatMessage
        throw std::runtime_error(std::string("Cannot load DLL: ")+filePath + std::string(" ") + std::to_string(lastError));
    }
    _lifecycleFn = reinterpret_cast<lifecycleFn_t>(::GetProcAddress(_handle, "greengrass_lifecycle"));
#endif
}

bool plugin::NativePlugin::isActive() {
    return _lifecycleFn;
}

void plugin::PluginLoader::lifecycle(data::Handle phase, const std::shared_ptr<data::Structish> & data) {
    // TODO: Run this inside of a task, right now we end up using calling threads task
    // However probably good to defer that until there's a basic lifecycle manager
    for (const auto &i : getPlugins()) {
        std::shared_ptr<AbstractPlugin> plugin {i->getObject<AbstractPlugin>()};
        if (plugin->isActive()) {
            plugin->lifecycle(data::Handle{i}, phase, data);
        }
    }
}

void plugin::NativePlugin::lifecycle(data::Handle pluginAnchor, data::Handle phase, const std::shared_ptr<data::Structish> & data) {
    lifecycleFn_t lifecycleFn = _lifecycleFn;
    if (lifecycleFn != nullptr) {
        std::shared_ptr<data::Structish> copy = data->copy();
        std::shared_ptr<tasks::Task> threadTask = _environment.handleTable.getObject<tasks::Task>(tasks::Task::getThreadSelf());
        std::shared_ptr<data::Anchored> dataAnchor = threadTask->anchor(copy.get());
        lifecycleFn(
                pluginAnchor.asInt(),
                phase.asInt(),
                data::Handle {dataAnchor}.asInt()
                );
    }
}

void plugin::DelegatePlugin::lifecycle(data::Handle pluginAnchor, data::Handle phase, const std::shared_ptr<data::Structish> & data) {
    uintptr_t delegateContext;
    ggapiLifecycleCallback delegateLifecycle;
    {
        std::shared_lock guard{_mutex};
        delegateContext = _delegateContext;
        delegateLifecycle = _delegateLifecycle;
    }
    if (delegateLifecycle != nullptr) {
        std::shared_ptr<data::Structish> copy = data->copy();
        std::shared_ptr<tasks::Task> threadTask = _environment.handleTable.getObject<tasks::Task>(tasks::Task::getThreadSelf());
        std::shared_ptr<data::Anchored> dataAnchor = threadTask->anchor(copy.get());
        delegateLifecycle(
                delegateContext,
                pluginAnchor.asInt(),
                phase.asInt(),
                data::Handle {dataAnchor}.asInt()
        );
    }
}

void plugin::PluginLoader::discoverPlugins() {
    // two-layer iterator just to make testing easier
    fs::path root = fs::absolute(".");
    for (const auto & top : fs::directory_iterator(root)) {
        if (top.is_regular_file()) {
            discoverPlugin(top);
        } else if (top.is_directory()) {
            for (const auto &fileEnt: fs::directory_iterator(top)) {
                if (fileEnt.is_regular_file()) {
                    discoverPlugin(fileEnt);
                }
            }
        }
    }
}

void plugin::PluginLoader::discoverPlugin(const fs::directory_entry &entry) {
    std::string name {entry.path().generic_string()};
#if defined(NATIVE_SUFFIX)
    if (entry.path().extension().compare(NATIVE_SUFFIX) == 0) {
        loadNativePlugin(name);
        return;
    }
#endif
}

void plugin::PluginLoader::loadNativePlugin(const std::string &name) {
    std::shared_ptr<NativePlugin> plugin {std::make_shared<NativePlugin>(_environment, name)};
    plugin->load(name);
    // add the plugin to collection by "anchoring"
    // which solves a number of interesting problems
    anchor(plugin.get());
}

std::vector<std::shared_ptr<data::Anchored>> plugin::PluginLoader::getPlugins() {
    std::shared_lock guard{_mutex};
    std::vector<std::shared_ptr<data::Anchored>> copy;
    copy.reserve(_roots.size());
    for (const auto &i : _roots) {
        copy.emplace_back(i.second);
    }
    return copy;
}

void plugin::PluginLoader::lifecycleBootstrap(const std::shared_ptr<data::Structish> & data) {
    data::Handle key = _environment.stringTable.getOrCreateOrd("bootstrap");
    lifecycle(key, data);
}

void plugin::PluginLoader::lifecycleDiscover(const std::shared_ptr<data::Structish> & data) {
    data::Handle key = _environment.stringTable.getOrCreateOrd("discover");
    lifecycle(key, data);
}

void plugin::PluginLoader::lifecycleStart(const std::shared_ptr<data::Structish> & data) {
    data::Handle key = _environment.stringTable.getOrCreateOrd("start");
    lifecycle(key, data);
}

void plugin::PluginLoader::lifecycleRun(const std::shared_ptr<data::Structish> & data) {
    data::Handle key = _environment.stringTable.getOrCreateOrd("run");
    lifecycle(key, data);
}

void plugin::PluginLoader::lifecycleTerminate(const std::shared_ptr<data::Structish> & data) {
    data::Handle key = _environment.stringTable.getOrCreateOrd("run");
    lifecycle(key, data);
}
