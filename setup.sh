#!/bin/bash

# This script automates the setup, compilation, and basic usage of the
# aya-rs eBPF firewall project for Debian-based systems.

# --- Global Variables ---
PROJECT_NAME="aya-firewall" # Renamed to avoid confusion with PROJECT_DIR
EBPF_CRATE="firewall-ebpf"
USER_CRATE="firewall-user"
# We will rely on `rustup install nightly --component complete`
# to find a suitable nightly version that has all required components.
NIGHTLY_TOOLCHAIN="nightly" # Use 'nightly' and let rustup find the specific date with --component complete

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

    log_info "Installing Rust nightly toolchain ($NIGHTLY_TOOLCHAIN) with complete components..."
    # `--component complete` will find a nightly version where all components are available.
    rustup install "$NIGHTLY_TOOLCHAIN" --component complete || log_error "Failed to install Rust nightly toolchain ($NIGHTLY_TOOLCHAIN) with complete components."

    # After installing, we need to know the *exact* date of the nightly installed by rustup.
    # This command gets the active nightly version and extracts the date.
    INSTALLED_NIGHTLY_DATE=$(rustup show active toolchain | grep -o 'nightly-[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}')
    if [ -z "$INSTALLED_NIGHTLY_DATE" ]; then
        log_error "Could not determine the exact date of the installed nightly toolchain. Please check rustup output."
    fi
    log_info "Determined installed nightly toolchain date: $INSTALLED_NIGHTLY_DATE"

    log_info "Adding bpfel-unknown-none target to Rustup $INSTALLED_NIGHTLY_DATE toolchain..."
    rustup target add bpfel-unknown-none --toolchain "$INSTALLED_NIGHTLY_DATE" || log_error "Failed to add bpfel-unknown-none target to $INSTALLED_NIGHTLY_DATE."

    log_info "Installing bpf-linker..."
    export PATH="$HOME/.cargo/bin:$PATH"
    if ! command -v bpf-linker &> /dev/null; then
        # Install bpf-linker using the specific nightly toolchain
        cargo +"$INSTALLED_NIGHTLY_DATE" install bpf-linker || log_error "Failed to install bpf-linker."
    else
        log_info "bpf-linker is already installed."
    fi
}

# Function to create project structure and files
create_project_structure() {
    log_info "Creating project directory: $PROJECT_NAME"
    mkdir -p "$PROJECT_NAME" || log_error "Failed to create project directory."
    pushd "$PROJECT_NAME" > /dev/null || log_error "Failed to change to project directory."

    log_info "Creating eBPF program crate ($EBPF_CRATE)..."
    cargo new --bin "$EBPF_CRATE" || log_error "Failed to create eBPF crate."

    log_info "Creating user-space application crate ($USER_CRATE)..."
    cargo new --bin "$USER_CRATE" || log_error "Failed to create user-space crate."

    log_info "Writing Cargo.toml for workspace root..."
    cat << EOF > Cargo.toml
# Cargo.toml (at the root of aya-firewall directory)
[workspace]
members = [
    "$EBPF_CRATE",
    "$USER_CRATE",
]
resolver = "2" # Explicitly use resolver version 2 for Edition 2021

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
    log_info "Workspace Cargo.toml created."

    log_info "Writing $EBPF_CRATE/Cargo.toml..."
    cat << EOF > "$EBPF_CRATE"/Cargo.toml
# $EBPF_CRATE/Cargo.toml
[package]
name = "$EBPF_CRATE"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-bpf = { version = "0.12.0", features = ["macros"] }
aya-log-ebpf = "0.1.0"

[[bin]]
name = "$EBPF_CRATE"
path = "src/main.rs"
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
    helpers::bpf_get_prandom_u32,
};
use aya_log_ebpf::info;

#[map(name = "RULES")]
static mut RULES: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn firewall_ebpf(ctx: XdpContext) -> u32 {
    match try_firewall_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => aya_bpf::programs::xdp::XDP_PASS,
    }
}

fn try_firewall_ebpf(ctx: XdpContext) -> Result<u32, i64> {
    info!(&ctx, "Received XDP packet from interface {}", ctx.ifindex());
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
aya = { version = "0.12.0", features = ["async_tokio"] }
aya-log = "0.1.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
clap = { version = "4", features = ["derive"] }
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
    bump_memlock_rlimit()?;

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes!(
        "../../target/bpfel-unknown-none/debug/firewall-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes!(
        "../../target/bpfel-unknown-none/release/firewall-ebpf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        eprintln!("Failed to initialize BPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("firewall_ebpf")
        .ok_or_else(|| anyhow::anyhow!("Program 'firewall_ebpf' not found"))?
        .try_into()?;

    program.load()?;
    program.attach(&args.iface, XdpFlags::SKB_MODE)
        .context(format!("Failed to attach XDP program to interface '{}'", args.iface))?;

    println!("eBPF firewall program loaded and attached to interface: {}", args.iface);
    println!("Press Ctrl-C to exit and detach the program.");
    signal::ctrl_c().await?;
    println!("Detaching eBPF program.");
    Ok(())
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        return Err(anyhow::any_how!("Failed to set rlimit: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}
EOF
    log_info "Project structure and files created successfully."
    popd > /dev/null
}

# Function to compile the project
compile_project() {
    log_info "Compiling eBPF program ($EBPF_CRATE)..."
    pushd "$PROJECT_NAME" > /dev/null || log_error "Failed to move to project directory for compilation."

    # Determine the actual installed nightly toolchain name (e.g., nightly-YYYY-MM-DD)
    INSTALLED_NIGHTLY_DATE=$(rustup show active toolchain | grep -o 'nightly-[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}')
    if [ -z "$INSTALLED_NIGHTLY_DATE" ]; then
        log_error "Could not determine the exact date of the installed nightly toolchain for compilation."
    fi
    log_info "Using installed nightly toolchain: $INSTALLED_NIGHTLY_DATE"


    log_info "Updating Cargo dependencies using $INSTALLED_NIGHTLY_DATE..."
    cargo +"$INSTALLED_NIGHTLY_DATE" update || log_error "Failed to update Cargo dependencies."

    log_info "Compiling eBPF program ($EBPF_CRATE) using $INSTALLED_NIGHTLY_DATE..."
    cargo +"$INSTALLED_NIGHTLY_DATE" build --workspace --release --target bpfel-unknown-none || log_error "Failed to compile eBPF program."
    log_info "eBPF program compiled."

    log_info "Compiling user-space application ($USER_CRATE) using $INSTALLED_NIGHTLY_DATE..."
    cargo +"$INSTALLED_NIGHTLY_DATE" build --workspace --release || log_error "Failed to compile user-space application."
    log_info "User-space application compiled."
    popd > /dev/null
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
