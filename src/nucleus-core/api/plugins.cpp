#include "../data/globals.h"
#include "../plugins/plugin_loader.h"
#include <c_api.h>

uint32_t ggapiRegisterPlugin(uint32_t moduleHandle, uint32_t componentName, ggapiLifecycleCallback lifecycleCallback, uintptr_t callbackContext) {
    data::Global & global = data::Global::self();
    std::shared_ptr<plugin::AbstractPlugin> parentModule { global.environment.handleTable.getObject<plugin::AbstractPlugin>(data::Handle{moduleHandle}) };
    std::shared_ptr<plugin::DelegatePlugin> delegate {std::make_shared<plugin::DelegatePlugin>(
            global.environment,
            global.environment.stringTable.getString(data::Handle{componentName}),
            parentModule,
            lifecycleCallback,
            callbackContext)};
    std::shared_ptr<data::Anchored> anchor = global.loader->anchor(delegate.get()); // TODO: schedule bootstrap cycle
    return data::Handle{anchor}.asInt();
}
