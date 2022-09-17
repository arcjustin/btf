# BTF Parser

## Description
Parsing library for the eBPF type format.

## Example Usage
```rust
use btf::BtfTypes;
use btf::types::Type;

let btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux")?;

if let Some(qt) = btf.resolve_type_by_name("do_mount") {
    if let Type::FunctionProto(fp) = qt.base_type {
        for param in fp.params {
            println!("{:?}", param);
        }
    }
}

if let Some(qt) = btf.resolve_type_by_name("task_struct") {
    if let Type::Struct(st) = qt.base_type {
        for member in st.members {
            println!("{:?}", member);
        }
    }
}
```
