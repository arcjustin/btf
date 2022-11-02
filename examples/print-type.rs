use btf::Btf;

use anyhow::{bail, Result};

use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        bail!("Invalid arguments.");
    }

    let btf = Btf::from_file(&args[1])?;
    println!("{:#?}", btf.get_type_by_name(&args[2]));

    Ok(())
}
