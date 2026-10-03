#pragma once

#include <cstdint>
#include "lynx/core/common.h"

namespace lynx {
    /**
     * @brief Stateless error value used to report operation failures.
     *
     * Carries an error status and its associated message. Error values are
     * returned by low-level socket helpers and are intended to be consumed by
     * the caller without maintaining any internal state.
     */
    struct Error {
        status      type = status::Ok;
        const char* msg  = nullptr;     // static string - never freed

        /**
         * @brief Checks whether an error is present.
         *
         * @return @c true if the error status is status::Ok; otherwise @c false.
         */
        [[nodiscard]] bool ok() const noexcept { 
            return type == status::Ok; 
        }

        /**
         * @brief Returns a human-readable description of the error.
         *
         * Returns the explicitly assigned error message when available; otherwise
         * falls back to the string representation of the error status.
         *
         * @return Null-terminated error description.
         */
        [[nodiscard]] const char* what() const noexcept {
            if (msg  && msg[0] != '\0') {
                return msg;
            }
            return nullptr;
        }

        /**
         * @brief Constructs an error value.
         *
         * @param s Error status.
         * @param m Optional static error message.
         *
         * @return Constructed error value.
         */
        [[nodiscard]] static Error make(status s, const char* m) noexcept {
            return { s, m };
        }

        /**
         * @brief Constructs an error value representing success.
         *
         * @return An error with status::Ok and no associated message.
         */
        [[nodiscard]] static Error none() noexcept {
            return { status::Ok, nullptr };
        }

        /**
         * @brief Clears the error state.
         *
         * Resets the error status to status::Ok and removes the associated message.
         */
        void clear() noexcept {
            type = status::Ok;
            msg  = nullptr;
        }
    };

} // namespace lynx
