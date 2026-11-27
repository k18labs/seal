use std::{
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const DEFAULT_CLI_TIMEOUT: Duration = Duration::from_secs(60);

pub fn run(command: &mut Command) -> Output {
    output_with_timeout(command, DEFAULT_CLI_TIMEOUT)
}

pub fn output_with_timeout(command: &mut Command, timeout: Duration) -> Output {
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start Seal CLI");
    wait_with_timeout(child, timeout)
}

pub fn wait_with_timeout(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("failed to poll Seal CLI").is_some() {
            return child
                .wait_with_output()
                .expect("failed to collect Seal CLI output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .expect("failed to collect timed-out Seal CLI output");
            panic!(
                "Seal CLI exceeded {timeout:?}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}
