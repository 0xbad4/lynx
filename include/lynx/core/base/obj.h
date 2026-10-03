#pragma once

#include "lynx/core/error.h"
#include "lynx/core/config/config.h"

namespace lynx {

    /**
     * @brief Base object providing common error state management.
     *
     * BaseObject is inherited by Interface, Packet, Buffer, and all protocol
     * layers. It carries the last error state produced by operations on the
     * object.
     *
     * Errors follow a first-error-wins policy: once an error is recorded, later
     * errors do not overwrite the original failure. This allows operations to
     * be chained and the final state checked once through ok(), while preserving
     * the root cause of the failure.
     */
    class BaseObject {
        public:
            [[nodiscard]] bool         ok() const noexcept { return err_.ok(); }
            [[nodiscard]] status       sts() const noexcept { return err_.type; }
            [[nodiscard]] const char*  errmsg() noexcept { return err_.what(); }
            [[nodiscard]] const Error& error() noexcept { return err_; }
        
            /**
             * @brief Clears the stored error state.
             *
             * Resets the object's error state, allowing it to be reused after an error
             * has been handled.
             *
             * This operation is explicit and is never performed automatically.
             */
            void clear_error() noexcept { err_.clear(); }
        
        protected:
            /**
             * @brief Records an error using the first-error-wins policy.
             *
             * If an error is already recorded, the existing error is preserved and the
             * supplied error is ignored.
             *
             * @param s Error status to record.
             * @param msg Error message associated with the status.
             */
            void set_error(status s, const char* msg) noexcept {
                if (err_.type != status::Ok) return;
                err_.type = s;
                err_.msg  = msg;
            }
        
            /**
             * @brief Absorbs an error into the object's error state.
             *
             * Records the supplied error only if it represents a failure and no previous
             * error has been recorded.
             *
             * @param e Error to absorb.
             */
            void absorb(const Error& e) noexcept {
                if (!e.ok()) {
                    set_error(e.type, e.msg);
                }
            }
        
            /**
             * @brief Replaces the current error state unconditionally.
             *
             * Unlike set_error(), this function overwrites an existing error. It should
             * only be used when intentionally replacing a stale error state.
             *
             * @param s Error status to record.
             * @param msg Error message associated with the status.
             */
            void overwrite_error(status s, const char* msg) noexcept {
                err_.type = s;
                err_.msg  = msg;
            }
        
        private:
            Error err_;
    };

} // namespace lynx
