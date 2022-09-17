pub mod btf;
pub mod types;

pub use crate::btf::*;

#[cfg(test)]
mod tests {
    use crate::types::Type;
    use crate::BtfTypes;

    #[test]
    fn load_vmlinux() {
        let vmlinux_types = BtfTypes::from_file("resources/vmlinux").unwrap();

        if let Some(qualified_type) = vmlinux_types.resolve_type_by_name("do_mount") {
            if let Type::FunctionProto(prototype) = qualified_type.base_type {
                for param in prototype.params {
                    println!("{:?}", param);
                }
            }
        }

        if let Some(qualified_type) = vmlinux_types.resolve_type_by_name("task_struct") {
            if let Type::Struct(structure) = qualified_type.base_type {
                for member in structure.members {
                    println!("{:?}", member);
                }
            }
        }
    }
}
