#![forbid(unsafe_code)]

fn main() {
    // The CLI dispatch future is large; run it on a dedicated thread with a generous stack
    // so debug builds on Windows (1 MB main-thread default) cannot overflow.
    let handle = std::thread::Builder::new()
        .name("vexa-main".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime")
                .block_on(vexa_sca::cli::run());
        })
        .expect("failed to spawn main thread");
    if handle.join().is_err() {
        std::process::exit(101);
    }
}
