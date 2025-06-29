#!/bin/bash

# This script automates the setup, compilation, and basic usage of the
# aya-rs eBPF firewall project for Debian-based systems.

# --- Global Variables ---
PROJECT_NAME="aya-firewall" # Renamed to avoid confusion with PROJECT_DIR
EBPF_CRATE="firewall-ebpf"
USER_CRATE="firewall-user"

# --- Functions ---

log_info() {
    echo -e "\e[32m[INFO]\e[0m $1"
}

log_warn() {
    echo -e "\e[33m[WARN]\e[0m $1"
}

log_error() {
    echo -e "\e[31m[ERROR]\e[0m $1"
    exit 1
}

# Function to check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo for prerequisite installation and eBPF program attachment."
    fi
}

# Function to install prerequisites
install_prerequisites() {
    log_info "Updating package lists..."
    sudo apt update || log_error "Failed to update apt package lists."

    log_info "Installing clang, llvm, libelf-dev, build-essential, and kernel headers..."
    sudo apt install -y clang llvm libelf-dev build-essential linux-headers-$(uname -r) || log_error "Failed to install core build tools and kernel headers."

    log_info "Installing Rust and Cargo..."
    if ! command -v rustup &> /dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # Source cargo env, but for the script's sake, we'll ensure paths later.
        source "$HOME/.cargo/env" || log_warn "Could not source Cargo environment, please ensure ~/.cargo/env is sourced in your shell."
    else
        log_info "Rust and Cargo are already installed."
    fi

    log_info "Installing bpf-linker..."
    # Ensure cargo is in PATH for this to work in a fresh environment
    export PATH="$HOME/.cargo/bin:$PATH"
    if ! command -v bpf-linker &> /dev/null; then
        cargo install bpf-linker || log_error "Failed to install bpf-linker."
    else
        log_info "bpf-linker is already installed."
    fi
}

# Function to create project structure and files
create_project_structure() {
    log_info "Creating project directory: $PROJECT_NAME"
    mkdir -p "$PROJECT_NAME" || log_error "Failed to create project directory."
    pushd "$PROJECT_NAME" > /dev/null || log_error "Failed to change to project directory."

    log_info "Initializing Rust workspace..."
    # Create a dummy lib package, then remove its src/lib.rs
    # This creates the workspace Cargo.toml with basic structure.
    cargo init --lib --name temp-workspace-init || log_error "Failed to initialize temporary workspace package."
    rm -rf src # Remove the dummy src directory
    rm Cargo.toml # Remove the temp Cargo.toml created by cargo init

    log_info "Writing Cargo.toml for workspace..."
    cat << EOF > Cargo.toml
[workspace]
members = [
    "$EBPF_CRATE",
    "$USER_CRATE",
]

[profile.release]
lto = true
strip = true
codegen-units = 1
EOF
    log_info "Workspace Cargo.toml created."

    log_info "Creating eBPF program crate ($EBPF_CRATE)..."
    cargo new --bin "$EBPF_CRATE" || log_error "Failed to create eBPF crate."

    log_info "Creating user-space application crate ($USER_CRATE)..."
    cargo new --bin "$USER_CRATE" || log_error "Failed to create user-space crate."

    log_info "Writing $EBPF_CRATE/Cargo.toml..."
    cat << EOF > "$EBPF_CRATE"/Cargo.toml
# $EBPF_CRATE/Cargo.toml
[package]
name = "$EBPF_CRATE"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-bpf = { version = "0.1.*", features = ["macros"] }
aya-log-ebpf = "0.1.*" # For logging from eBPF

[[bin]]
name = "$EBPF_CRATE"
path = "src/main.rs"

[profile.dev]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false

[profile.release]
lto = true
panic = "abort"
codegen-units = 1
strip = true
EOF

    log_info "Writing $EBPF_CRATE/src/main.rs..."
    cat << EOF > "$EBPF_CRATE"/src/main.rs
// $EBPF_CRATE/src/main.rs
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{xdp, map},
    programs::XdpContext,
    maps::HashMap,
    helpers::bpf_get_prandom_u32, // Example helper for future use
};
use aya_log_ebpf::info;

// Define a HashMap for storing allow/deny rules (example for future expansion)
// Key: IPv4 address (u32), Value: action (u8, e.g., 0 for DENY, 1 for ALLOW)
#[map(name = "RULES")]
static mut RULES: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// XDP program entry point
// XDP (eXpress Data Path) programs run very early in the network stack.
#[xdp]
pub fn firewall_ebpf(ctx: XdpContext) -> u32 {
    match try_firewall_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => aya_bpf::programs::xdp::XDP_PASS, // On error, just pass the packet
    }
}

fn try_firewall_ebpf(ctx: XdpContext) -> Result<u32, i64> {
    info!(&ctx, "Received XDP packet from interface {}", ctx.ifindex());

    // In a real firewall, you would parse the packet (Ethernet, IP, TCP/UDP headers)
    // to inspect source/destination IPs, ports, protocols, etc.
    // For this basic example, we'll just pass all packets.

    // Example of using a map (not fully implemented for filtering yet, just for demonstration):
    // let ip_addr = 0x7F000001; // Example: 127.0.0.1
    // if let Some(action) = unsafe { RULES.get(&ip_addr) } {
    //     if *action == 0 { // If action is DENY
    //         info!(&ctx, "Packet from 127.0.0.1 DENIED by rule!");
    //         return Ok(aya_bpf::programs::xdp::XDP_DROP);
    //     }
    // }

    // For now, always pass the packet.
    // XDP_PASS: Pass the packet to the normal network stack.
    // XDP_DROP: Drop the packet.
    // XDP_TX: Transmit the packet back out the same interface.
    // XDP_REDIRECT: Redirect the packet to another interface or CPU.
    Ok(aya_bpf::programs::xdp::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
EOF

    log_info "Writing $USER_CRATE/Cargo.toml..."
    cat << EOF > "$USER_CRATE"/Cargo.toml
# $USER_CRATE/Cargo.toml
[package]
name = "$USER_CRATE"
version = "0.1.0"
edition = "2021"

[dependencies]
aya = { version = "0.1.*", features = ["async_tokio"] }
aya-log = "0.1.*"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
clap = { version = "4", features = ["derive"] } # For command-line arguments
anyhow = "1.0"
EOF

    log_info "Writing $USER_CRATE/src/main.rs..."
    cat << EOF > "$USER_CRATE"/src/main.rs
// $USER_CRATE/src/main.rs
use aya::{
    Bpf,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::BpfLogger;
use clap::Parser;
use tokio::signal;
use anyhow::{Context, Result};
use std::convert::TryInto;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Bump the memlock limit. This is often required for eBPF programs.
    // This allows the process to lock more memory, which eBPF programs need.
    // 'rlimit' is "resource limit".
    bump_memlock_rlimit()?;

    // Load the eBPF program from the compiled BPF object file.
    // The BPF object file is generated when you build firewall-ebpf.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes!(
        "../../target/bpfel-unknown-none/debug/firewall-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes!(
        "../../target/bpfel-unknown-none/release/firewall-ebpf"
    ))?;

    // Initialize the BPF logger, which allows your user-space app to receive logs
    // from your eBPF program.
    if let Err(e) = BpfLogger::init(&mut bpf) {
        eprintln!("Failed to initialize BPF logger: {}", e);
    }

    // Get the XDP program named "firewall_ebpf" from the loaded BPF object.
    let program: &mut Xdp = bpf.program_mut("firewall_ebpf")
        .ok_or_else(|| anyhow::anyhow!("Program 'firewall_ebpf' not found"))?
        .try_into()?;

    // Attach the XDP program to the specified network interface.
    // XdpFlags::SKB_MODE attaches the program in SKB (Socket Buffer) mode,
    // which is generally safer but slightly less performant than DRV (Driver) mode.
    // DRV mode requires driver support and direct interaction with the NIC.
    program.load()?;
    program.attach(&args.iface, XdpFlags::SKB_MODE)
        .context(format!("Failed to attach XDP program to interface '{}'", args.iface))?;

    println!("eBPF firewall program loaded and attached to interface: {}", args.iface);
    println!("Press Ctrl-C to exit and detach the program.");

    // Example of interacting with an eBPF map:
    // let mut rules_map: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("RULES")?)?;
    // let ip_to_block: u32 = 0x0100007F; // 127.0.0.1 in network byte order (little-endian: 1.0.0.127)
    // rules_map.insert(ip_to_block, 0, 0)?; // Insert rule: 127.0.0.1 -> DENY (0)
    // println!("Added example rule to block 127.0.0.1 to eBPF map.");

    // Wait for Ctrl-C signal to gracefully detach and exit.
    signal::ctrl_c().await?;
    println!("Detaching eBPF program.");

    // The program is automatically detached when it goes out of scope or the process exits.
    Ok(())
}

// Helper function to bump the memlock rlimit.
// eBPF programs require the ability to lock memory pages.
fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        return Err(anyhow::anyhow!("Failed to set rlimit: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}
EOF
    log_info "Project structure and files created successfully."
    popd > /dev/null # Go back to the original directory
}

# Function to compile the project
compile_project() {
    log_info "Compiling eBPF program ($EBPF_CRATE)..."
    # Ensure we're in the project root for workspace build
    pushd "$PROJECT_NAME" > /dev/null || log_error "Failed to move to project directory for compilation."
    cargo build --workspace --release --target bpfel-unknown-none || log_error "Failed to compile eBPF program."
    log_info "eBPF program compiled."

    log_info "Compiling user-space application ($USER_CRATE)..."
    cargo build --workspace --release || log_error "Failed to compile user-space application."
    log_info "User-space application compiled."
    popd > /dev/null # Go back to the original directory
}

# Function to run the firewall
run_firewall() {
    local interface="$1"
    if [[ -z "$interface" ]]; then
        log_error "Usage: sudo ./setup.sh run <interface_name>"
    fi
    log_info "Running eBPF firewall on interface: $interface"
    sudo "./$PROJECT_NAME/target/release/$USER_CRATE" -i "$interface" || log_error "Failed to run firewall."
}

# --- Main Script Logic ---
case "$1" in
    setup)
        check_root
        install_prerequisites
        create_project_structure
        compile_project
        log_info "Setup complete. You can now run the firewall using: sudo ./setup.sh run <interface>"
        ;;
    run)
        check_root
        run_firewall "$2"
        ;;
    *)
        log_info "Usage: "
        log_info "  sudo ./setup.sh setup    - Installs prerequisites, sets up project, and compiles."
        log_info "  sudo ./setup.sh run <interface> - Runs the compiled firewall on the specified network interface (e.g., eth0, lo)."
        ;;
esac
