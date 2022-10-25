use btf::BtfTypes;

use std::env;

fn main() -> Result<(), u32> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: print-type <btf_file> <type_name>");
        return Err(1);
    }

    let btf = match BtfTypes::from_file(&args[1]) {
        Ok(btf) => btf,
        Err(e) => {
            println!("Failed to parse BTF file: {}.", e);
            return Err(1);
        }
    };

    if let Some(ty) = btf.resolve_type_by_name(&args[2]) {
        println!("{:#?}", ty);
        Ok(())
    } else {
        println!("Type with name \"{}\" doesn't exist.", args[2]);
        Err(2)
    }
}
