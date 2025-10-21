//! # tcping-rs Library
//!
//! A Rust library for TCP port reachability testing, providing functionality
//! similar to traditional ping but for specific TCP ports.
//!
//! This library allows you to:
//! - Test TCP port connectivity
//! - Measure round-trip time (RTT) to TCP endpoints
//! - Gather statistics about connection attempts
//! - Support multiple output formats (normal, JSON, CSV, Markdown, colored)
//!
//! ## Example Usage
//!
//! ```rust
//! use tcping::cli::Args;
//! use tcping::engine;
//! use clap::Parser;
//!
//! // Create arguments programmatically
//! let args = Args {
//!     address: "google.com:443".to_string(),
//!     count: 4,
//!     continuous: false,
//!     output_mode: tcping::cli::OutputMode::Normal,
//!     exit_on_success: false,
//!     jitter: false,
//!     timeout_ms: 2000,
//! };
//!
//! // Run the engine
//! let result = engine::run(args);
//! match result {
//!     Ok(exit_code) => println!("Completed with exit code: {}", exit_code),
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! ```

pub mod cli;
pub mod engine;
pub mod error;
pub mod formatter;
pub mod probe;
pub mod stats;

/// Windows-specific performance optimizations
#[cfg(windows)]
pub mod win_boost {
    //! Lightweight FFI wrappers for high-resolution timing & priority.

    #[link(name = "winmm")]
    unsafe extern "system" {
        fn timeBeginPeriod(period: u32) -> u32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetThreadPriority(thread: *mut core::ffi::c_void, priority: i32) -> i32;
        fn GetCurrentThread() -> *mut core::ffi::c_void;
    }

    /// Enable high-resolution timer on Windows (1ms precision)
    pub fn enable_high_res_timer() {
        // SAFETY: official API; 1 ms is always valid.
        unsafe { timeBeginPeriod(1) };
    }

    /// Elevate current thread priority to highest level
    pub fn elevate_thread_priority() {
        const THREAD_PRIORITY_HIGHEST: i32 = 2;
        // SAFETY: current thread handle is always valid.
        unsafe {
            let th = GetCurrentThread();
            SetThreadPriority(th, THREAD_PRIORITY_HIGHEST);
        }
    }
}

/// Enable Windows-specific performance optimizations
#[cfg(windows)]
pub fn enable_windows_boost() {
    win_boost::enable_high_res_timer();
    win_boost::elevate_thread_priority();
}
