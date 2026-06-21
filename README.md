# Remzar Blockchain

Remzar is a sovereign Layer 1 blockchain implementation written in Rust.

Remzar is designed for secure value transfer, wallet-based identity, verified records, certificate-style digital proofs, peer-to-peer node participation, and post-quantum blockchain infrastructure.

This repository contains the public Remzar mainnet source code and build instructions for running a Remzar node.

## Network

| Field                | Value            |
| -------------------- | ---------------- |
| Network              | `mainnet`        |
| Mainnet genesis date | `June 26, 2026`  |
| Chain ID             | `remzar-mainnet` |
| Protocol version     | `1`              |
| Software version     | `1.0.0`          |
| License              | `MIT`            |

## Release Status

Remzar v1.0.0 is the first official public release of the Remzar mainnet node software.

The project is distributed as public Rust source code and as a ready-to-run Windows application package.

## Features

Remzar includes:

* Layer 1 blockchain node implementation
* Mainnet chain configuration
* Peer-to-peer node participation
* Wallet creation and encrypted wallet storage
* Transaction sending and receiving
* Balance checking
* Blockchain activity viewing
* Certificate-style digital proof tools
* Audit and support utilities
* Diagnostic build mode
* Post-quantum cryptographic components
* Windows release binary support
* Windows application icon embedding through `build.rs`
* Strict core-library safety rules
* Unit, integration, and fuzz testing coverage

## Repository Layout

remzar/
  Cargo.toml
  Cargo.lock
  README.md
  LICENSE
  CHANGELOG.md
  build.rs
  assets/
    remzar.ico
  node1/
    genesis.json
  src/
    lib.rs
    main.rs
    core/
  tests/
  fuzz/

## Requirements

To build Remzar from source, install:

* Rust 1.85 or newer
* Cargo
* Git
* Windows PowerShell

Remzar uses the Rust 2024 edition.

## Build Remzar

From the root of the repository, run:

cargo clean
cargo build --release

After a successful build, the optimized Windows binary is created at:

target\release\remzar.exe

## Create the Public Windows Package

After the release build succeeds, create the public runtime package:

$SourceFolder = (Resolve-Path ".").Path
$RemzarFolder = Join-Path $SourceFolder "target\Remzar-Public"

New-Item -ItemType Directory -Path $RemzarFolder -Force
New-Item -ItemType Directory -Path (Join-Path $RemzarFolder "data") -Force

Copy-Item (Join-Path $SourceFolder "target\release\remzar.exe") `
          (Join-Path $RemzarFolder "remzar.exe") -Force

Copy-Item (Join-Path $SourceFolder "node1\genesis.json") `
          (Join-Path $RemzarFolder "genesis.json") -Force

Set-Location $RemzarFolder
Get-ChildItem

A successful package step creates this folder:

target\Remzar-Public\

The `Remzar-Public` folder contains:

Remzar-Public\
  remzar.exe
  genesis.json
  data\

The `data` folder is created empty. Remzar uses it at runtime.

## Run Remzar

From the public package folder:

Set-Location "target\Remzar-Public"
.\remzar.exe

The application starts the Remzar menu interface.

Through the menu, users can create wallets, run a node, send and receive Remzar, check balances, view blockchain activity, create or verify proofs, access audit tools, and exit safely.

## Recommended Windows Runtime Location

For normal Windows use, copy the public package to:

C:\Remzar-Public

Then run:

Set-Location "C:\Remzar-Public"
.\remzar.exe

## Run From Source

Developers can run Remzar directly from the source tree:

cargo run --release

For normal interactive use, start Remzar without manual networking flags. Node and networking options are handled through the application menu.

## Genesis File

The Remzar mainnet genesis file defines the starting state of the chain.

The public runtime package includes:

genesis.json

If the genesis export test is enabled, the genesis file can be regenerated with:

$env:REMZAR_GENESIS_EXPORT="YES"
cargo test --test file_genesis_file_tests export_genesis_json_for_chain -- --ignored --nocapture
Remove-Item Env:REMZAR_GENESIS_EXPORT

## Tests

Remzar includes a test suite for the core blockchain implementation.

The public release test coverage includes:

* 250+ unit and integration tests
* 51 fuzz targets
* Mainnet genesis validation
* Core blockchain logic tests
* Wallet and transaction tests
* Runtime and node safety checks
* Error-handling tests
* Release-mode verification

Run the standard test suite:

cargo test

Run release-mode tests:

cargo test --release

Recommended pre-release verification:

cargo clean
cargo test
cargo test --release
cargo build --release

## Fuzz Testing

Remzar includes fuzz targets under the `fuzz/` directory.

List available fuzz targets:

cd fuzz
cargo fuzz list

Run a fuzz target:

cargo fuzz run <target-name>

The public release includes 51 fuzz targets.

## Code Safety Standards

The Remzar core library is written with strict safety and auditability rules.

The core library forbids unsafe Rust:

#![forbid(unsafe_code)]

The core modules are expected to pass strict Clippy checks for production and library code.

Baseline Clippy check:

cargo clippy --all-features -- -D warnings

The core lint policy is designed to reduce unsafe behavior, panics, unchecked arithmetic, hidden allocations, accidental unwraps, indexing errors, large stack usage, and other patterns that can create reliability or consensus risks.

## Windows Icon Support

Remzar includes a Windows build script that embeds the application icon into the compiled executable.

The icon file is located at:

assets\remzar.ico

The build script is:

build.rs

When building on Windows, the icon is embedded into `remzar.exe`.

## Diagnostic Build

Remzar includes a diagnostic mode for debugging and support.

Build diagnostic mode:

cargo clean
cargo build --release --no-default-features --features diagnostic

Create the diagnostic package:

$SourceFolder = (Resolve-Path ".").Path
$RemzarFolder = Join-Path $SourceFolder "target\Remzar-Diagnostic"

New-Item -ItemType Directory -Path $RemzarFolder -Force
New-Item -ItemType Directory -Path (Join-Path $RemzarFolder "data") -Force

Copy-Item (Join-Path $SourceFolder "target\release\remzar.exe") `
          (Join-Path $RemzarFolder "remzar-diagnostic.exe") -Force

Copy-Item (Join-Path $SourceFolder "node1\genesis.json") `
          (Join-Path $RemzarFolder "genesis.json") -Force

Set-Location $RemzarFolder
Get-ChildItem

Run diagnostic mode:

Set-Location "target\Remzar-Diagnostic"
$env:RUST_LOG = "trace"
.\remzar-diagnostic.exe

## Running a Node

A Remzar node can be started by running:

.\remzar.exe

When the application opens, use the built-in menu to configure and run the node.

For normal users, the recommended flow is:

1. Start `remzar.exe`.
2. Create or open a wallet.
3. Back up the wallet.
4. Start the node from the menu.
5. Use the menu to send, receive, verify, audit, or view chain activity.
6. Exit through the built-in safe shutdown option.

## Wallet Safety

Users are responsible for their wallet, passphrase, and backups.

Important wallet rules:

* Write down the wallet passphrase and store it safely.
* Back up the wallet file after creating a wallet.
* Keep wallet backups separate from the computer running Remzar.
* Never share a passphrase.
* Never share private keys.
* Never send wallet files to anyone.
* Verify recipient addresses before sending funds.
* Use the built-in safe shutdown option before closing Remzar.

If a wallet passphrase is lost, the wallet may not be recoverable.

## Sending and Receiving Remzar

Use the built-in application menu to send and receive Remzar.

Before sending, confirm:

* The sender wallet
* The recipient address
* The amount
* The transaction details
* The selected wallet

Blockchain transactions may be irreversible once submitted.

## Digital Proofs, Certificates, and Records

Remzar includes tools for creating and verifying certificate-style digital records.

Depending on the release, Remzar may support:

* Certificates
* Digital identity records
* NFT-style proofs
* Badge-style records
* Legal or document proof records
* Real-world asset proof records
* Exportable proof files
* Audit receipts

Users should verify all information before submitting records to the network.

## Troubleshooting

### Application does not start

Try the following:

* Confirm the file is named `remzar.exe`.
* Run Remzar from a simple folder path such as `C:\Remzar-Public`.
* Restart the computer and try again.
* Check whether Windows security software blocked the file.

### Node does not connect

Try the following:

* Check the internet connection.
* Allow network access when Windows asks for permission.
* Make sure the system clock is accurate.
* Restart the application.
* Start the node again from the menu.

### Wallet cannot be opened

Check that:

* The correct wallet was selected.
* The correct passphrase was entered.
* The wallet file was not moved, renamed, or deleted.
* The correct backup file is being used.

### Balance looks incorrect

Try the following:

* Let the node finish syncing.
* Restart the application.
* Recheck the wallet address.
* Confirm the correct wallet is open.

## Changelog

See `CHANGELOG.md`.

Initial release:

[1.0.0] - 2026-06-26
- First official release.
- Core features are stable and production-ready.

## Official Links

* Website: https://www.remzar.com/
* Repository: https://github.com/remzarchain/remzar
* Contact: [remzarchain@gmail.com](mailto:remzarchain@gmail.com)

## License

Remzar is released under the MIT License.

See the `LICENSE` file for details.