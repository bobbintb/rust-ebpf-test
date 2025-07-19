use aya::programs::KProbe;
#[rustfmt::skip]
use log::{debug, info, warn, Log, Record, Level, Metadata};
use tokio::signal;
use std::sync::mpsc;
use std::thread;
use serde_json::{Value, json};

// Custom log handler to intercept log messages
struct LogHandler {
    sender: mpsc::Sender<String>,
    original_logger: env_logger::Logger,
}

impl LogHandler {
    fn new(sender: mpsc::Sender<String>) -> Self {
        LogHandler {
            sender,
            original_logger: env_logger::Builder::new().build(),
        }
    }
}

impl Log for LogHandler {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.original_logger.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let message = format!("{}", record.args());
            
            // Send the message to our processor thread
            let _ = self.sender.send(message.clone());
            
            // Also log using the original logger if it's not a JSON message
            if !message.contains("DIRT_JSON:") {
                self.original_logger.log(record);
            }
        }
    }

    fn flush(&self) {
        self.original_logger.flush();
    }
}

// Function to convert byte array to readable string
fn bytes_to_string(bytes: &[u64]) -> String {
    bytes.iter()
        .map(|&b| {
            if b >= 32 && b <= 126 {
                char::from_u32(b as u32).unwrap_or('?')
            } else {
                '?'
            }
        })
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Set default log level to Info if RUST_LOG is not set
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env)
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_millis()
        .format_module_path(false)
        .format_target(false)
        .init();

    info!("=== DIRT eBPF File Deletion Monitor Starting ===");
    info!("Monitoring file deletions via vfs_unlink system calls");
    info!("You'll see detailed process information for each deletion");

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("DIRT: Failed to remove limit on locked memory, ret: {ret}");
    } else {
        debug!("DIRT: Successfully set memlock limit to infinity");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    info!("DIRT: Loading eBPF program...");
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;
    
    info!("DIRT: Initializing eBPF logger...");
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("DIRT: Failed to initialize eBPF logger: {e}");
    } else {
        info!("DIRT: eBPF logger initialized successfully");
    }
    
    // Attach the existing kretprobe
    info!("DIRT: Loading and attaching kretprobe 'dirt'...");
    let dirt_program: &mut KProbe = ebpf.program_mut("dirt").unwrap().try_into()?;
    dirt_program.load()?;
    dirt_program.attach("vfs_unlink", 0)?;
    info!("DIRT: kretprobe 'dirt' attached successfully to vfs_unlink");
    
    // Attach the new kprobe for vfs_unlink
    info!("DIRT: Loading and attaching kprobe 'vfs_unlink_probe'...");
    let vfs_unlink_program: &mut KProbe = ebpf.program_mut("vfs_unlink_probe").unwrap().try_into()?;
    vfs_unlink_program.load()?;
    vfs_unlink_program.attach("vfs_unlink", 0)?;
    info!("DIRT: kprobe 'vfs_unlink_probe' attached successfully to vfs_unlink");

    info!("DIRT: === Monitoring Active ===");
    info!("DIRT: Both probes are now active and monitoring file deletions");
    info!("DIRT: Each deletion will show structured JSON output with event type, process info, file inode, filename length, filename preview, and return values");
    info!("DIRT: Try deleting a file to see detailed output!");
    info!("DIRT: Example: 'touch /tmp/test && rm /tmp/test' in another terminal");
    info!("DIRT: You can use 'ps -p <PID>' to see which process is deleting files");
    
    // Start a thread to process logs and enhance JSON output
    info!("DIRT: Starting JSON output processor...");
    
    // Create a pipe for log processing
    let (tx, rx) = std::sync::mpsc::channel();
    
    // Clone the transmitter for the log handler
    let tx_clone = tx.clone();
    
    // Set up a custom log handler
    let _ = log::set_boxed_logger(Box::new(LogHandler::new(tx_clone)))
        .map(|()| log::set_max_level(log::LevelFilter::Info));
    
    // Start the log processor thread
    let _processor = thread::spawn(move || {
        for message in rx {
            if message.contains("DIRT_JSON:") {
                if let Some(json_start) = message.find('{') {
                    if let Some(json_end) = message.rfind('}') {
                        let json_str = &message[json_start..=json_end];
                        
                        // Parse the JSON
                        if let Ok(mut json_value) = serde_json::from_str::<Value>(json_str) {
                            // Convert filename_preview to a readable string
                            if let Some(preview_array) = json_value.get("filename_preview").and_then(Value::as_array) {
                                let filename_str = bytes_to_string(
                                    &preview_array.iter()
                                        .filter_map(|v| v.as_u64())
                                        .collect::<Vec<u64>>()
                                );
                                
                                // Add the string representation to the JSON
                                if let Some(obj) = json_value.as_object_mut() {
                                    obj.insert("filename".to_string(), json!(filename_str));
                                }
                                
                                println!("[INFO] DIRT_JSON_ENHANCED: {}", json_value.to_string());
                            } else {
                                println!("{}", message);
                            }
                        } else {
                            println!("{}", message);
                        }
                    } else {
                        println!("{}", message);
                    }
                } else {
                    println!("{}", message);
                }
            } else {
                println!("{}", message);
            }
        }
    });
    
    let ctrl_c = signal::ctrl_c();
    println!("DIRT: Waiting for Ctrl-C to stop monitoring...");
    ctrl_c.await?;
    println!("DIRT: Shutting down file deletion monitor...");

    Ok(())
}
