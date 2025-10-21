// Example usage of tcping as a library
use tcping::cli::{Args, OutputMode};
use tcping::engine;

fn main() -> tcping::error::Result<()> {
    // Example 1: Basic usage
    println!("=== Basic TCP ping ===");
    let args = Args {
        address: "google.com:443".to_string(),
        count: 3,
        continuous: false,
        output_mode: OutputMode::Normal,
        exit_on_success: false,
        jitter: false,
        timeout_ms: 2000,
    };
    
    let exit_code = engine::run(args)?;
    println!("Basic ping completed with exit code: {}\n", exit_code);

    // Example 2: JSON output
    println!("=== TCP ping with JSON output ===");
    let args_json = Args {
        address: "httpbin.org:80".to_string(),
        count: 2,
        continuous: false,
        output_mode: OutputMode::Json,
        exit_on_success: false,
        jitter: true,
        timeout_ms: 3000,
    };
    
    let exit_code_json = engine::run(args_json)?;
    println!("JSON ping completed with exit code: {}", exit_code_json);

    Ok(())
}