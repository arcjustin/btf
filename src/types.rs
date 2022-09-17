use std::cmp::Ordering;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::mem::size_of;

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd)]
pub enum TypeKind {
    #[default]
    Void = 0,
    Integer = 1,
    Pointer = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum32 = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Function = 12,
    FunctionProto = 13,
    Variable = 14,
    DataSection = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

#[derive(Clone, Debug)]
pub struct Integer {
    pub id: u32,
    pub name: String,
    pub size: u32,
    pub bits: u8,
    pub is_signed: bool,
    pub is_char: bool,
    pub is_bool: bool,
    pub offset: u16,
}

#[derive(Clone, Debug)]
pub struct TypeMap {
    pub id: u32,
    pub type_id: u32,
}

#[derive(Clone, Debug)]
pub struct Array {
    pub id: u32,
    pub size: u32,
    pub element_type: u32,
    pub index_type: u32,
    pub num_elements: u32,
}

#[derive(Clone, Debug)]
pub struct StructMember {
    pub name: String,
    pub type_id: u32,
    pub bitfield_size: u32,
    pub offset: u32,
}

#[derive(Clone, Debug)]
pub struct Struct {
    pub id: u32,
    pub name: String,
    pub size: u32,
    pub members: HashMap<String, StructMember>,
}

#[derive(Clone, Debug)]
pub struct EnumEntry {
    pub name: String,
    pub value: i64,
}

#[derive(Clone, Debug)]
pub struct Enum {
    pub id: u32,
    pub name: String,
    pub size: u32,
    pub entries: HashMap<String, EnumEntry>,
}

#[derive(Clone, Debug)]
pub struct Fwd {
    pub id: u32,
    pub name: String,
    pub is_union: bool,
}

#[derive(Clone, Debug)]
pub struct Typedef {
    pub id: u32,
    pub name: String,
    pub type_id: u32,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub id: u32,
    pub name: String,
    pub linkage: LinkageKind,
    pub type_id: u32,
}

#[derive(Clone, Debug)]
pub struct FunctionParam {
    pub name: String,
    pub type_id: u32,
}

#[derive(Clone, Debug)]
pub struct FunctionProto {
    pub id: u32,
    pub params: Vec<FunctionParam>,
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd)]
pub enum LinkageKind {
    #[default]
    Static,
    Global,
}

#[derive(Clone, Debug)]
pub struct Variable {
    pub id: u32,
    pub name: String,
    pub linkage: LinkageKind,
}

#[derive(Clone, Debug)]
pub struct SectionInfo {
    pub id: u32,
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(Clone, Debug)]
pub struct DataSection {
    pub id: u32,
    pub name: String,
    pub sections: Vec<SectionInfo>,
}

#[derive(Clone, Debug)]
pub struct Float {
    pub id: u32,
    pub name: String,
    pub size: u32,
}

#[derive(Clone, Debug)]
pub struct DeclTag {
    pub id: u32,
    pub name: String,
    pub component_index: u32,
}

#[derive(Clone, Debug)]
pub struct TypeTag {
    pub id: u32,
    pub name: String,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd)]
pub enum Type {
    #[default]
    Void,
    Integer(Integer),
    Pointer(TypeMap),
    Array(Array),
    Struct(Struct),
    Union(Struct),
    Enum32(Enum),
    Fwd(Fwd),
    Typedef(Typedef),
    Volatile(TypeMap),
    Const(TypeMap),
    Restrict(TypeMap),
    Function(Function),
    FunctionProto(FunctionProto),
    Variable(Variable),
    DataSection(DataSection),
    Float(Float),
    DeclTag(DeclTag),
    TypeTag(TypeTag),
    Enum64(Enum),
}

impl Type {
    pub fn get_id(&self) -> Option<u32> {
        match self {
            Self::Integer(s) => Some(s.id),
            Self::Struct(s) => Some(s.id),
            Self::Union(s) => Some(s.id),
            Self::Enum32(s) => Some(s.id),
            Self::Fwd(s) => Some(s.id),
            Self::Typedef(s) => Some(s.id),
            Self::Function(s) => Some(s.id),
            Self::Variable(s) => Some(s.id),
            Self::DataSection(s) => Some(s.id),
            Self::Float(s) => Some(s.id),
            Self::DeclTag(s) => Some(s.id),
            Self::TypeTag(s) => Some(s.id),
            Self::Enum64(s) => Some(s.id),
            _ => None,
        }
    }

    pub fn get_name(&self) -> &str {
        match self {
            Self::Integer(s) => &s.name,
            Self::Struct(s) => &s.name,
            Self::Union(s) => &s.name,
            Self::Enum32(s) => &s.name,
            Self::Fwd(s) => &s.name,
            Self::Typedef(s) => &s.name,
            Self::Function(s) => &s.name,
            Self::Variable(s) => &s.name,
            Self::DataSection(s) => &s.name,
            Self::Float(s) => &s.name,
            Self::DeclTag(s) => &s.name,
            Self::TypeTag(s) => &s.name,
            Self::Enum64(s) => &s.name,
            _ => "<anonymous>",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct QualifiedType {
    pub base_type: Type,
    pub num_refs: u32,
    pub is_typedef: bool,
    pub is_volatile: bool,
    pub is_constant: bool,
    pub is_restrict: bool,
    pub is_function: bool,
}

impl QualifiedType {
    pub fn int<T>() -> Self {
        Self {
            base_type: Type::Integer(Integer {
                id: 0,
                name: String::from(""),
                size: size_of::<T>() as u32,
                bits: (size_of::<T>() * 8) as u8,
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
            }),
            num_refs: 0,
            is_typedef: false,
            is_volatile: false,
            is_constant: true,
            is_restrict: false,
            is_function: false,
        }
    }

    pub fn is_pointer(&self) -> bool {
        self.num_refs != 0
    }

    pub fn get_size(&self) -> u32 {
        if self.is_pointer() {
            return 8; // This is true for BPF only.
        }

        match &self.base_type {
            Type::Integer(t) => t.size,
            Type::Struct(t) => t.size,
            Type::Union(t) => t.size,
            Type::Float(t) => t.size,
            Type::Array(t) => t.size,
            Type::Enum32(t) => t.size,
            Type::Enum64(t) => t.size,
            _ => 0,
        }
    }
}

macro_rules! derive_relations_from_field {
    ($s:ident, $f:ident) => {
        impl Hash for $s {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.$f.hash(state);
            }
        }

        impl PartialEq for $s {
            fn eq(&self, other: &Self) -> bool {
                self.$f == other.$f
            }
        }

        impl Eq for $s {}

        impl PartialOrd for $s {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.$f.cmp(&other.$f))
            }
        }

        impl Ord for $s {
            fn cmp(&self, other: &Self) -> Ordering {
                self.$f.cmp(&other.$f)
            }
        }
    };
}

derive_relations_from_field!(Integer, id);
derive_relations_from_field!(TypeMap, id);
derive_relations_from_field!(Array, id);
derive_relations_from_field!(StructMember, name);
derive_relations_from_field!(Struct, id);
derive_relations_from_field!(EnumEntry, name);
derive_relations_from_field!(Enum, id);
derive_relations_from_field!(Fwd, id);
derive_relations_from_field!(Typedef, id);
derive_relations_from_field!(Function, id);
derive_relations_from_field!(FunctionParam, name);
derive_relations_from_field!(FunctionProto, id);
derive_relations_from_field!(Variable, id);
derive_relations_from_field!(DataSection, id);
derive_relations_from_field!(Float, id);
derive_relations_from_field!(DeclTag, id);
derive_relations_from_field!(TypeTag, id);
