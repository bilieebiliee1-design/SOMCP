// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (C) 2026 bilieebiliee1-design
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// std::atomic_ref compatibility shim.
//
// Android NDK r29 ships libc++ 18.1.8, which does not provide std::atomic_ref
// (P0019R8, a C++20 feature that libc++ only implemented in v19). Dart SDK
// revisions that are compiled with -std=c++20 use std::atomic_ref in runtime
// headers (e.g. runtime/vm/raw_object.h, runtime/vm/field_table.h), so the
// NDK cross-build fails with "no member named 'atomic_ref' in namespace 'std'".
//
// This header is force-included (-include) into every C++ translation unit of
// the Dart VM cross-build (see build_runner.py and android-runner/CMakeLists.txt).
// It is intentionally harmless everywhere else:
//   * <atomic> is included first so the __cpp_lib_atomic_ref feature-test macro
//     reflects the real standard library (no redefinition when it exists);
//   * the shim body is only emitted for C++20 builds whose standard library
//     lacks std::atomic_ref.
//
// The implementation maps each operation onto the GCC/Clang __atomic_*
// builtins, which is exactly what libc++'s own atomic_ref does internally.

#ifndef DART_VM_ATOMIC_REF_COMPAT_H_
#define DART_VM_ATOMIC_REF_COMPAT_H_

#if defined(__cplusplus) && __cplusplus >= 202002L

#include <atomic>
#include <cstddef>
#include <type_traits>

#if !defined(__cpp_lib_atomic_ref)

namespace std {

template <typename T>
class atomic_ref {
 public:
  static_assert(is_trivially_copyable<T>::value,
                "atomic_ref requires a trivially copyable type");

  static constexpr size_t required_alignment = alignof(T);
  static constexpr bool is_always_lock_free =
      __atomic_always_lock_free(sizeof(T), nullptr);

  atomic_ref(T& obj) noexcept : ptr_(&obj) {}
  atomic_ref(const atomic_ref&) noexcept = default;
  atomic_ref& operator=(const atomic_ref&) noexcept = delete;

  bool is_lock_free() const noexcept {
    return __atomic_is_lock_free(sizeof(T), ptr_) != 0;
  }

  T load(memory_order order = memory_order_seq_cst) const noexcept {
    T result;
    __atomic_load(ptr_, &result, order_to_builtin(order));
    return result;
  }

  void store(T value, memory_order order = memory_order_seq_cst) const noexcept {
    __atomic_store(ptr_, &value, order_to_builtin(order));
  }

  T exchange(T value,
             memory_order order = memory_order_seq_cst) const noexcept {
    T result;
    __atomic_exchange(ptr_, &value, &result, order_to_builtin(order));
    return result;
  }

  bool compare_exchange_weak(T& expected,
                             T desired,
                             memory_order success,
                             memory_order failure) const noexcept {
    return __atomic_compare_exchange(ptr_, &expected, &desired, true,
                                     order_to_builtin(success),
                                     order_to_builtin(failure));
  }

  bool compare_exchange_weak(T& expected,
                             T desired,
                             memory_order order = memory_order_seq_cst) const
      noexcept {
    return compare_exchange_weak(expected, desired, order, order);
  }

  bool compare_exchange_strong(T& expected,
                               T desired,
                               memory_order success,
                               memory_order failure) const noexcept {
    return __atomic_compare_exchange(ptr_, &expected, &desired, false,
                                     order_to_builtin(success),
                                     order_to_builtin(failure));
  }

  bool compare_exchange_strong(T& expected,
                               T desired,
                               memory_order order = memory_order_seq_cst) const
      noexcept {
    return compare_exchange_strong(expected, desired, order, order);
  }

  template <typename U = T,
            typename enable_if<is_integral<U>::value, int>::type = 0>
  T fetch_add(T value,
              memory_order order = memory_order_seq_cst) const noexcept {
    return __atomic_fetch_add(ptr_, value, order_to_builtin(order));
  }

  template <typename U = T,
            typename enable_if<is_integral<U>::value, int>::type = 0>
  T fetch_sub(T value,
              memory_order order = memory_order_seq_cst) const noexcept {
    return __atomic_fetch_sub(ptr_, value, order_to_builtin(order));
  }

  template <typename U = T,
            typename enable_if<is_integral<U>::value, int>::type = 0>
  T fetch_and(T value,
              memory_order order = memory_order_seq_cst) const noexcept {
    return __atomic_fetch_and(ptr_, value, order_to_builtin(order));
  }

  template <typename U = T,
            typename enable_if<is_integral<U>::value, int>::type = 0>
  T fetch_or(T value,
             memory_order order = memory_order_seq_cst) const noexcept {
    return __atomic_fetch_or(ptr_, value, order_to_builtin(order));
  }

  template <typename U = T,
            typename enable_if<is_integral<U>::value, int>::type = 0>
  T fetch_xor(T value,
              memory_order order = memory_order_seq_cst) const noexcept {
    return __atomic_fetch_xor(ptr_, value, order_to_builtin(order));
  }

 private:
  static int order_to_builtin(memory_order order) noexcept {
    switch (order) {
      case memory_order_relaxed:
        return __ATOMIC_RELAXED;
      case memory_order_consume:
        return __ATOMIC_CONSUME;
      case memory_order_acquire:
        return __ATOMIC_ACQUIRE;
      case memory_order_release:
        return __ATOMIC_RELEASE;
      case memory_order_acq_rel:
        return __ATOMIC_ACQ_REL;
      case memory_order_seq_cst:
        return __ATOMIC_SEQ_CST;
    }
    return __ATOMIC_SEQ_CST;
  }

  T* ptr_;
};

template <typename T>
atomic_ref(T&) -> atomic_ref<T>;

}  // namespace std

#endif  // !defined(__cpp_lib_atomic_ref)

#endif  // defined(__cplusplus) && __cplusplus >= 202002L

#endif  // DART_VM_ATOMIC_REF_COMPAT_H_
