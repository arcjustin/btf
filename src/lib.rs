//! [![Build Status](https://github.com/arcjustin/btf/workflows/build/badge.svg)](https://github.com/arcjustin/btf/actions?query=workflow%3Abuild)
//! [![crates.io](https://img.shields.io/crates/v/btf.svg)](https://crates.io/crates/btf)
//! [![mio](https://docs.rs/btf/badge.svg)](https://docs.rs/btf/)
//! [![Lines of Code](https://tokei.rs/b1/github/arcjustin/btf?category=code)](https://tokei.rs/b1/github/arcjustin/btf?category=code)
//!
//! Parsing library for the eBPF type format.
//!
//! ## Usage
//!
//! ```
//! use btf::Btf;
//!
//! let btf = Btf::from_file("/sys/kernel/btf/vmlinux").expect("Failed to parse vmlinux");
//! let pt_regs = btf.get_type_by_name("pt_regs").expect("Can't find type.");
//! println!("{:?}", pt_regs);
//! ```
//!
//! ## License
//!
//! * [MIT license](http://opensource.org/licenses/MIT)
pub mod btf;
pub mod error;

pub use crate::btf::*;
pub use crate::error::*;
