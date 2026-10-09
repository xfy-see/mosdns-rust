// SPDX-License-Identifier: GPL-3.0-or-later
#[cfg(feature = "full")]
pub mod api;
pub mod coremain;
pub mod pkg;
pub mod plugin;
#[cfg(feature = "full")]
pub mod tools;

#[cfg(all(feature = "full", feature = "minimal"))]
compile_error!(
    "full and minimal are separate profiles; use --no-default-features --features minimal"
);
