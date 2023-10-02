#include "shared_list.h"

namespace data {

    void SharedList::rootsCheck(const ContainerModelBase *target) const { // NOLINT(*-no-recursion)
        if (this == target) {
            throw std::runtime_error("Recursive reference of container");
        }
        // we don't want to keep nesting locks else we will deadlock
        std::shared_lock guard {_mutex };
        std::vector<std::shared_ptr<ContainerModelBase>> containers;
        for (auto const & i : _elements) {
            if (i.isContainer()) {
                std::shared_ptr<ContainerModelBase> otherContainer = i.getContainer();
                if (otherContainer) {
                    containers.emplace_back(otherContainer);
                }
            }
        }
        guard.release();
        for (auto const & i : containers) {
            i->rootsCheck(target);
        }
    }

    std::shared_ptr<ListModelBase> SharedList::copy() const {
        std::shared_ptr<SharedList> newCopy {std::make_shared<SharedList>(_environment)};
        std::shared_lock guard {_mutex}; // for source
        newCopy->_elements = _elements; // shallow copy
        return newCopy;
    }

    void SharedList::put(int32_t idx, const StructElement & element) {
        checkedPut(element, [this,idx](auto & el) {
            std::unique_lock guard {_mutex };
            size_t realIdx;
            if (idx < 0) {
                realIdx = _elements.size() + idx;
            } else {
                realIdx = idx;
            }
            if (realIdx > _elements.size()) {
                throw std::out_of_range("Put index out of range");
            } else if (_elements.size() >= MAX_LIST_SIZE) {
                throw std::out_of_range("List too large");
            } else if (realIdx == _elements.size()) {
                _elements.push_back(el);
            } else {
                _elements[idx] = el;
            }
        });
    }

    void SharedList::insert(int32_t idx, const StructElement & element) {
        checkedPut(element, [this,idx](auto & el) {
            std::unique_lock guard {_mutex };
            size_t realIdx;
            if (idx < 0) {
                realIdx = _elements.size() + idx + 1; // -1 inserts at end
            } else {
                realIdx = idx;
            }
            if (realIdx > _elements.size()) {
                throw std::out_of_range("Put index out of range");
            } else if (_elements.size() >= MAX_LIST_SIZE) {
                throw std::out_of_range("List too large");
            } else if (realIdx == _elements.size()) {
                _elements.push_back(el);
            } else {
                _elements.insert(_elements.begin()+idx, el);
            }
        });
    }

    uint32_t SharedList::size() const {
        std::shared_lock guard {_mutex};
        return _elements.size();
    }

    StructElement SharedList::get(int32_t idx) const {
        std::shared_lock guard {_mutex};
        size_t realIdx;
        if (idx < 0) {
            realIdx = _elements.size() + idx;
        } else {
            realIdx = idx;
        }
        if (realIdx >= _elements.size()) {
            return {};
        } else {
            return _elements[idx];
        }
    }

}
