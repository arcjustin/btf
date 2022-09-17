pub mod btf;
pub mod types;

pub use crate::btf::*;

#[cfg(test)]
mod tests {
    use crate::types::Type;
    use crate::BtfTypes;

    #[test]
    fn load_vmlinux() {
        let btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux").unwrap();

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
    }
}
