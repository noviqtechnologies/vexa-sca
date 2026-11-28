#![forbid(unsafe_code)]

//! Shared pure-Rust security primitives consumed by `vexa-sca`, `vexa-arc`,
//! and `vexa-sca-cloud` so CLI, local agent runtime, and cloud control plane
//! evaluate CVSS, OpenSSF `MAL-*` malware, lockfile graphs, and JS/TS AST
//! reachability using one authoritative engine.

pub mod ai_bom;
pub mod cvss;
pub mod fs_guard;
pub mod js_ast;
pub mod malware;
pub mod py_ast;
pub mod python_lock;
