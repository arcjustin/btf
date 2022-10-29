use crate::types::Type;
use crate::BtfTypes;

use std::mem::size_of;

pub trait AddToBtf {
    /// Types implementing this trait can be added to an existing
    /// BTF type database.
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// struct MyStruct {
    ///     pub a: u32,
    /// }
    ///
    /// impl AddToBtf for MyStruct {
    ///     fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
    ///         btf.add_struct("MyStruct", &[("a", "u32")])
    ///     }
    /// }
    ///
    /// let mut btf = BtfTypes::default();
    /// u32::add_to_btf(&mut btf).expect("Failed to add u32.");
    /// MyStruct::add_to_btf(&mut btf).expect("Bad type definition");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type>;
}

impl AddToBtf for u8 {
    /// Trait implementation for adding Rust's u8 type to an existing
    /// BTF type database. This is added to the database as an 8-bit,
    /// unsigned integer with the name "u8".
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// u8::add_to_btf(&mut btf).expect("Failed to add u8.");
    /// btf.get_type_by_name("u8").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("u8").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("u8", 1, false)
    }
}

impl AddToBtf for u16 {
    /// Trait implementation for adding Rust's u16 type to an existing
    /// BTF type database. This is added to the database as an 16-bit,
    /// unsigned integer with the name "u16".
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// u16::add_to_btf(&mut btf).expect("Failed to add u16.");
    /// btf.get_type_by_name("u16").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("u16").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("u16", 2, false)
    }
}

impl AddToBtf for u32 {
    /// Trait implementation for adding Rust's u32 type to an existing
    /// BTF type database. This is added to the database as an 32-bit,
    /// unsigned integer with the name "u32".
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// u32::add_to_btf(&mut btf).expect("Failed to add u32.");
    /// btf.get_type_by_name("u32").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("u32").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("u32", 4, false)
    }
}

impl AddToBtf for u64 {
    /// Trait implementation for adding Rust's u64 type to an existing
    /// BTF type database. This is added to the database as an 64-bit,
    /// unsigned integer with the name "u64".
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// u64::add_to_btf(&mut btf).expect("Failed to add u64.");
    /// btf.get_type_by_name("u64").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("u64").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("u64", 8, false)
    }
}

impl AddToBtf for i8 {
    /// Trait implementation for adding Rust's i8 type to an existing
    /// BTF type database. This is added to the database as an 8-bit,
    /// signed integer with the name "i8".
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// i8::add_to_btf(&mut btf).expect("Failed to add i8.");
    /// btf.get_type_by_name("i8").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("i8").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("i8", 1, true)
    }
}

impl AddToBtf for i16 {
    /// Trait implementation for adding Rust's i16 type to an existing
    /// BTF type database. This is added to the database as an 16-bit,
    /// signed integer with the name "i16".
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// i16::add_to_btf(&mut btf).expect("Failed to add i16.");
    /// btf.get_type_by_name("i16").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("i16").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("i16", 2, true)
    }
}

impl AddToBtf for i32 {
    /// Trait implementation for adding Rust's i32 type to an existing
    /// BTF type database. This is added to the database as an 32-bit,
    /// signed integer with the name "i32".
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// i32::add_to_btf(&mut btf).expect("Failed to add i32.");
    /// btf.get_type_by_name("i32").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("i32").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("i32", 4, true)
    }
}

impl AddToBtf for i64 {
    /// Trait implementation for adding Rust's i64 type to an existing
    /// BTF type database. This is added to the database as an 64-bit,
    /// signed integer with the name "i64".
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// i64::add_to_btf(&mut btf).expect("Failed to add i64.");
    /// btf.get_type_by_name("i64").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("i64").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("i64", 8, true)
    }
}

impl AddToBtf for usize {
    /// Trait implementation for adding Rust's usize type to an existing
    /// BTF type database. The size is different on different platforms;
    /// it's the amount of bytes needed to reference any memory location.
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// usize::add_to_btf(&mut btf).expect("Failed to add usize.");
    /// btf.get_type_by_name("usize").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("usize").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("usize", size_of::<usize>().try_into().ok()?, false)
    }
}

impl AddToBtf for isize {
    /// Trait implementation for adding Rust's isize type to an existing
    /// BTF type database. The size is different on different platforms;
    /// it's the amount of bytes needed to reference any memory location.
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// isize::add_to_btf(&mut btf).expect("Failed to add isize.");
    /// btf.get_type_by_name("isize").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("isize").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        btf.add_integer("isize", size_of::<isize>().try_into().ok()?, true)
    }
}

impl<T: AddToBtf, const N: usize> AddToBtf for [T; N] {
    /// Generic trait implemenation for adding arrays to a BTF type database.
    ///
    /// # Arguments
    ///
    /// * `btf` - The database to which the type is to be added.
    ///
    /// # Example
    /// ```
    /// use btf::{AddToBtf, BtfTypes, Type};
    ///
    /// let mut btf = BtfTypes::default();
    /// <[i64; 5]>::add_to_btf(&mut btf).expect("Failed to add type.");
    /// btf.get_type_by_name("[i64; 5]").expect("New type doesn't exist.");
    /// btf.resolve_type_by_name("[i64; 5]").expect("New type can't be resolved.");
    /// ```
    fn add_to_btf(btf: &mut BtfTypes) -> Option<&Type> {
        usize::add_to_btf(btf)?;
        T::add_to_btf(btf)?;
        btf.add_array(
            &format!("[{}; {}]", std::any::type_name::<T>(), N),
            "usize",
            std::any::type_name::<T>(),
            N.try_into().expect("Array size too large"),
        )
    }
}
