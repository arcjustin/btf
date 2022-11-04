use crate::{Error, Result};

use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::path::Path;

/// Represents a parsed BTF file header (struct btf_header).
#[derive(Clone, Copy, Debug, Default)]
struct Header<B> {
    _version: u8,
    _flags: u8,
    hdr_len: u32,

    /* all offsets are in bytes relative to the end of this header */
    type_off: u32,
    type_len: u32,
    str_off: u32,
    _str_len: u32,

    endianess: PhantomData<B>,
}

impl<B: ByteOrder> Header<B> {
    /// Parses a BTF header.
    ///
    /// # Arguments
    /// * `reader` - The reader from which the header is read.
    fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            _version: reader.read_u8()?,
            _flags: reader.read_u8()?,
            hdr_len: reader.read_u32::<B>()?,
            type_off: reader.read_u32::<B>()?,
            type_len: reader.read_u32::<B>()?,
            str_off: reader.read_u32::<B>()?,
            _str_len: reader.read_u32::<B>()?,
            endianess: PhantomData,
        })
    }

    /// Read a string from the reader using the header as a reference.
    ///
    /// # Arguments
    /// * `reader` - The reader from which the string is read.
    /// * `offset` - The offset of the string.
    fn read_string<R: Read + Seek + BufRead>(
        &self,
        reader: &mut R,
        offset: u32,
    ) -> Result<Option<String>> {
        let oldpos = reader.stream_position()?;
        reader.seek(SeekFrom::Start(
            self.hdr_len as u64 + self.str_off as u64 + offset as u64,
        ))?;

        let mut raw_str = vec![];
        reader.read_until(0, &mut raw_str)?;
        raw_str.pop().ok_or(Error::Parsing {
            offset: reader.stream_position()?,
            message: "Reading raw string returned an empty buffer",
        })?;
        reader.seek(SeekFrom::Start(oldpos))?;

        match std::str::from_utf8(&raw_str) {
            Ok(s) => Ok(Some(s.into())),
            Err(_) => Err(Error::Parsing {
                offset: reader.stream_position()?,
                message: "Failed to decode string",
            }),
        }
    }

    /// Reads the type section of the BTF blob contained in reader.
    ///
    /// # Arguments
    /// * `reader` - The reader from which the types are read.
    fn read_types<R: Read + Seek + BufRead>(&self, reader: &mut R) -> Result<Vec<ParsedType>> {
        reader.seek(SeekFrom::Start(self.hdr_len as u64 + self.type_off as u64))?;
        let start_pos = reader.stream_position()?;
        let end_pos = start_pos + self.type_len as u64;

        let mut types = vec![ParsedType::default()];
        loop {
            let type_header = TypeHeader::from_reader::<B, _>(reader, self)?;
            let ty = Type::from_reader::<B, _>(reader, &type_header, self)?;
            types.push(ParsedType {
                header: type_header,
                ty,
            });

            match reader.stream_position()? {
                pos if pos > end_pos => {
                    return Err(Error::Parsing {
                        offset: reader.stream_position()?,
                        message: "Type length didn't match end of file",
                    });
                }
                pos if pos == end_pos => break,
                _ => (),
            }
        }

        Ok(types)
    }
}

/// All types representable by BTF.
#[derive(Clone, Copy, Debug, Default)]
enum TypeKind {
    #[default]
    Void,
    Integer,
    Pointer,
    Array,
    Struct,
    Union,
    Enum32,
    Fwd,
    Typedef,
    Volatile,
    Const,
    Restrict,
    Function,
    FunctionProto,
    Variable,
    DataSection,
    Float,
    DeclTag,
    TypeTag,
    Enum64,
}

/// Represents a parsed BTF type header (struct type_header).
#[derive(Clone, Debug, Default)]
struct TypeHeader {
    /// "name_off" parsed for convenience into a Rust String.
    name: Option<String>,

    /// "info" encoded bits.
    ///
    /// bits  0-15: vlen (e.g. # of struct's members)
    /// bits 16-23: unused
    /// bits 24-28: kind (e.g. int, ptr, array...etc)
    /// bits 29-30: unused
    /// bit     31: kind_flag, currently used by
    ///             struct, union, fwd, enum and enum64.
    ///
    info: u32,

    /// "size"/"type" is a union field.
    ///
    /// "size" is used by INT, ENUM, STRUCT, UNION and ENUM64.
    /// "size" tells the size of the type it is describing.
    ///
    /// "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
    /// FUNC, FUNC_PROTO, DECL_TAG and TYPE_TAG.
    /// "type" is a type_id referring to another type.
    ///
    size_type: u32,
}

impl TypeHeader {
    /// Parses a BTF type header. This is the C `struct bpf_type`, type.
    ///
    /// # Arguments
    /// * `reader` - The reader from which the type is read.
    /// * `header` - The header associated with this type.
    fn from_reader<B: ByteOrder, R: Read + Seek + BufRead>(
        reader: &mut R,
        header: &Header<B>,
    ) -> Result<TypeHeader> {
        let name_off = reader.read_u32::<B>()?;
        let name = header.read_string(reader, name_off)?;
        let info = reader.read_u32::<B>()?;
        let size_type = reader.read_u32::<B>()?;

        Ok(Self {
            name,
            info,
            size_type,
        })
    }

    /// Returns the kind field, see the documentation for this structure.
    fn get_kind(&self) -> Result<TypeKind> {
        match (self.info >> 24) & 0x1f {
            x if x == TypeKind::Void as u32 => Ok(TypeKind::Void),
            x if x == TypeKind::Integer as u32 => Ok(TypeKind::Integer),
            x if x == TypeKind::Pointer as u32 => Ok(TypeKind::Pointer),
            x if x == TypeKind::Array as u32 => Ok(TypeKind::Array),
            x if x == TypeKind::Struct as u32 => Ok(TypeKind::Struct),
            x if x == TypeKind::Union as u32 => Ok(TypeKind::Union),
            x if x == TypeKind::Enum32 as u32 => Ok(TypeKind::Enum32),
            x if x == TypeKind::Fwd as u32 => Ok(TypeKind::Fwd),
            x if x == TypeKind::Typedef as u32 => Ok(TypeKind::Typedef),
            x if x == TypeKind::Volatile as u32 => Ok(TypeKind::Volatile),
            x if x == TypeKind::Const as u32 => Ok(TypeKind::Const),
            x if x == TypeKind::Restrict as u32 => Ok(TypeKind::Restrict),
            x if x == TypeKind::Function as u32 => Ok(TypeKind::Function),
            x if x == TypeKind::FunctionProto as u32 => Ok(TypeKind::FunctionProto),
            x if x == TypeKind::Variable as u32 => Ok(TypeKind::Variable),
            x if x == TypeKind::DataSection as u32 => Ok(TypeKind::DataSection),
            x if x == TypeKind::Float as u32 => Ok(TypeKind::Float),
            x if x == TypeKind::DeclTag as u32 => Ok(TypeKind::DeclTag),
            x if x == TypeKind::TypeTag as u32 => Ok(TypeKind::TypeTag),
            x if x == TypeKind::Enum64 as u32 => Ok(TypeKind::Enum64),
            x => Err(Error::UnknownType { type_num: x }),
        }
    }

    /// Returns the vlen field, see the documentation for this structure.
    fn get_vlen(&self) -> u16 {
        self.info as u16
    }

    /// Returns the kind flag, see the documentation for this structure.
    fn get_kind_flag(&self) -> bool {
        ((self.info >> 31) & 0x1) == 0x1
    }

    /// Returns the type, see the documentation for this structure.
    fn get_type(&self) -> u32 {
        self.size_type
    }

    /// Returns the size, see the documentation for this structure.
    fn get_size(&self) -> u32 {
        self.size_type
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Integer {
    pub used_bits: u32,
    pub bits: u32,
    pub is_signed: bool,
    pub is_char: bool,
    pub is_bool: bool,
}

impl Integer {
    /// Reads a BTF encoded integer (BTF_KIND_INT).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    /// * `type_header` - The BTF type header that was read for this type.
    fn from_reader<B: ByteOrder, R: Read>(
        reader: &mut R,
        type_header: &TypeHeader,
    ) -> Result<Self> {
        let kind_specific = reader.read_u32::<B>()?;
        let bits = kind_specific as u8;
        let is_signed = (kind_specific >> 24) & 0x1 == 0x1;
        let is_char = (kind_specific >> 24) & 0x2 == 0x2;
        let is_bool = (kind_specific >> 24) & 0x4 == 0x4;
        Ok(Self {
            bits: type_header.size_type * 8,
            used_bits: bits.into(),
            is_signed,
            is_char,
            is_bool,
        })
    }
}

/// There are multiple BTF types that simply map to other types like:
/// Pointer, Typedef, etc.. This is used to represent those mappings.
#[derive(Clone, Copy, Debug, Default)]
pub struct TypeMap {
    pub type_id: u32,
}

impl TypeMap {
    /// Creates a type map from a given BTF type header.
    ///
    /// # Arguments
    /// * `type_header` - The BTF type header that was read for this type.
    fn from_type_header(type_header: &TypeHeader) -> Self {
        Self {
            type_id: type_header.get_type(),
        }
    }
}

/// Represents a parsed BTF array (struct btf_array).
#[derive(Clone, Copy, Debug, Default)]
pub struct Array {
    pub elem_type_id: u32,
    pub index_type_id: u32,
    pub num_elements: u32,
}

impl Array {
    /// Reads a BTF encoded array (struct btf_array).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    fn from_reader<B: ByteOrder, R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            elem_type_id: reader.read_u32::<B>()?,
            index_type_id: reader.read_u32::<B>()?,
            num_elements: reader.read_u32::<B>()?,
        })
    }
}

/// Represents a parsed BTF structure member (struct btf_member).
#[derive(Clone, Debug, Default)]
pub struct StructMember {
    pub name: Option<String>,
    pub type_id: u32,
    pub offset: u32,
    pub bits: Option<u32>,
}

impl StructMember {
    /// Reads a BTF encoded structure member (struct btf_member).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    /// * `type_header` - The BTF type header that was read for this type.
    /// * `header` - The header associated with this type.
    fn from_reader<B: ByteOrder, R: Read + Seek + BufRead>(
        reader: &mut R,
        type_header: &TypeHeader,
        header: &Header<B>,
    ) -> Result<StructMember> {
        let name_off = reader.read_u32::<B>()?;
        let name = header.read_string(reader, name_off)?;
        let type_id = reader.read_u32::<B>()?;
        let offset_and_bits = reader.read_u32::<B>()?;

        let (offset, bits) = if type_header.get_kind_flag() {
            (offset_and_bits & 0xffffff, Some(offset_and_bits >> 24))
        } else {
            (offset_and_bits, None)
        };

        Ok(StructMember {
            name,
            type_id,
            offset,
            bits,
        })
    }
}

/// Represents a parsed BTF structure ([struct btf_member]).
#[derive(Clone, Debug, Default)]
pub struct Struct {
    pub members: Vec<StructMember>,
}

impl Struct {
    /// Reads a BTF encoded structure ([struct btf_member]).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    /// * `type_header` - The BTF type header that was read for this type.
    /// * `header` - The header associated with this type.
    fn from_reader<B: ByteOrder, R: Read + Seek + BufRead>(
        reader: &mut R,
        type_header: &TypeHeader,
        header: &Header<B>,
    ) -> Result<Self> {
        let num_members = type_header.get_vlen();
        let mut members = Vec::<StructMember>::with_capacity(num_members.into());
        for _ in 0..num_members {
            members.push(StructMember::from_reader::<B, _>(
                reader,
                type_header,
                header,
            )?);
        }

        Ok(Struct { members })
    }
}

/// Represents a parsed BTF enum member (struct btf_enum).
#[derive(Clone, Debug, Default)]
pub struct EnumEntry {
    pub name: Option<String>,
    pub value: i64,
}

impl EnumEntry {
    /// Reads a BTF encoded enum member (struct btf_enum).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    /// * `header` - The header associated with this type.
    fn from_reader<B: ByteOrder, R: Read + Seek + BufRead, const WIDE: bool>(
        reader: &mut R,
        header: &Header<B>,
    ) -> Result<Self> {
        let name_off = reader.read_u32::<B>()?;
        let name = header.read_string(reader, name_off)?;
        let value = if WIDE {
            reader.read_i32::<B>()? as i64 | ((reader.read_i32::<B>()? as i64) << 32)
        } else {
            reader.read_i32::<B>()? as i64
        };

        Ok(EnumEntry { name, value })
    }
}

/// Represents a parsed BTF enum ([struct btf_enum]).
#[derive(Clone, Debug, Default)]
pub struct Enum {
    pub is_signed: bool,
    pub entries: Vec<EnumEntry>,
}

impl Enum {
    /// Reads a BTF encoded enum member ([struct btf_enum]).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    /// * `type_header` - The BTF type header that was read for this type.
    /// * `header` - The header associated with this type.
    fn from_reader<B: ByteOrder, R: Read + Seek + BufRead>(
        reader: &mut R,
        type_header: &TypeHeader,
        header: &Header<B>,
    ) -> Result<Self> {
        let is_signed = type_header.get_kind_flag();
        let num_entries = type_header.get_vlen();
        let mut entries = Vec::<EnumEntry>::with_capacity(num_entries.into());
        match type_header.get_kind() {
            Ok(TypeKind::Enum32) => {
                for _ in 0..num_entries {
                    entries.push(EnumEntry::from_reader::<B, _, false>(reader, header)?);
                }
            }
            Ok(TypeKind::Enum64) => {
                for _ in 0..num_entries {
                    entries.push(EnumEntry::from_reader::<B, _, true>(reader, header)?);
                }
            }
            _ => return Err(Error::InvalidEnumTypeKind),
        };

        Ok(Self { is_signed, entries })
    }
}

/// Represents a parsed BTF forward-declaration.
#[derive(Clone, Copy, Debug, Default)]
pub enum Fwd {
    #[default]
    Struct,
    Union,
}

impl Fwd {
    /// Creates a forward-declaration type from a BTF type header.
    ///
    /// # Arguments
    /// * `type_header` - The BTF type header that was read for this type.
    fn from_type_header(type_header: &TypeHeader) -> Self {
        if type_header.get_kind_flag() {
            Self::Union
        } else {
            Self::Struct
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum LinkageKind {
    #[default]
    Static,
    Global,
}

/// Represents a parsed BTF function.
#[derive(Clone, Copy, Debug, Default)]
pub struct Function {
    pub linkage: LinkageKind,
    pub type_id: u32,
}

impl Function {
    /// Creates a function type from a raw type header.
    ///
    /// # Arguments
    /// * `type_header` - The BTF type header that was read for this type.
    fn from_type_header(type_header: &TypeHeader) -> Self {
        let linkage = if type_header.get_vlen() == 0 {
            LinkageKind::Static
        } else {
            LinkageKind::Global
        };

        Self {
            linkage,
            type_id: type_header.get_type(),
        }
    }
}

/// Represents a parsed BTF function parameter (struct btf_param).
#[derive(Clone, Debug, Default)]
pub struct FunctionParam {
    pub name: Option<String>,
    pub type_id: u32,
}

impl FunctionParam {
    /// Reads a BTF encoded function parameter (struct btf_param).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    /// * `header` - The header associated with this type.
    fn from_reader<B: ByteOrder, R: Read + Seek + BufRead>(
        reader: &mut R,
        header: &Header<B>,
    ) -> Result<Self> {
        let name_off = reader.read_u32::<B>()?;
        let name = header.read_string(reader, name_off)?;
        let type_id = reader.read_u32::<B>()?;

        Ok(Self { name, type_id })
    }
}

/// Represents a parsed BTF function prototype ([struct btf_param]).
#[derive(Clone, Debug, Default)]
pub struct FunctionProto {
    pub params: Vec<FunctionParam>,
}

impl FunctionProto {
    /// Reads a BTF encoded function ([struct btf_param]).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    /// * `type_header` - The BTF type header that was read for this type.
    /// * `header` - The header associated with this type.
    fn from_reader<B: ByteOrder, R: Read + Seek + BufRead>(
        reader: &mut R,
        type_header: &TypeHeader,
        header: &Header<B>,
    ) -> Result<Self> {
        let num_params = type_header.get_vlen();
        let mut params = Vec::with_capacity(num_params.into());
        for _ in 0..num_params {
            params.push(FunctionParam::from_reader::<B, _>(reader, header)?);
        }

        Ok(Self { params })
    }
}

/// Represents a parsed BTF variable type (struct btf_var).
#[derive(Clone, Copy, Debug, Default)]
pub struct Variable {
    pub linkage: LinkageKind,
}

impl Variable {
    /// Reads a BTF encoded variable (struct btf_var).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    fn from_reader<B: ByteOrder, R: Read>(reader: &mut R) -> Result<Self> {
        let linkage = match reader.read_u32::<B>()? {
            0 => LinkageKind::Static,
            1 => LinkageKind::Global,
            _ => return Err(Error::InvalidLinkageKind),
        };

        Ok(Self { linkage })
    }
}

/// Represents a parsed BTF section variable (struct btf_var_secinfo).
#[derive(Clone, Copy, Debug, Default)]
pub struct SectionVariable {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

impl SectionVariable {
    /// Reads a BTF encoded section variable (struct btf_var_secinfo).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    fn from_reader<B: ByteOrder, R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            type_id: reader.read_u32::<B>()?,
            offset: reader.read_u32::<B>()?,
            size: reader.read_u32::<B>()?,
        })
    }
}

/// Represents a parsed BTF data section ([struct btf_var_secinfo]).
#[derive(Clone, Debug, Default)]
pub struct DataSection {
    pub vars: Vec<SectionVariable>,
}

impl DataSection {
    /// Reads a BTF encoded data section ([struct btf_var_secinfo]).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    /// * `type_header` - The BTF type header that was read for this type.
    fn from_reader<B: ByteOrder, R: Read>(
        reader: &mut R,
        type_header: &TypeHeader,
    ) -> Result<Self> {
        let num_vars = type_header.get_vlen();
        let mut vars = Vec::with_capacity(num_vars.into());
        for _ in 0..num_vars {
            vars.push(SectionVariable::from_reader::<B, _>(reader)?)
        }

        Ok(Self { vars })
    }
}

/// Represents a parsed BTF float.
#[derive(Clone, Copy, Debug, Default)]
pub struct Float {
    pub bits: u32,
}

impl Float {
    /// Creates a float type from a raw type header.
    ///
    /// # Arguments
    /// * `type_header` - The BTF type header that was read for this type.
    fn from_type_header(type_header: &TypeHeader) -> Self {
        Self {
            bits: type_header.get_size() * 8,
        }
    }
}

/// Represents a parsed BTF decl tag.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeclTag {
    pub component_index: u32,
}

impl DeclTag {
    /// Reads a BTF encoded decl tag (struct btf_decl_tag).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    fn from_reader<B: ByteOrder, R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            component_index: reader.read_u32::<B>()?,
        })
    }
}

/// Represents a parsed BTF type.
#[derive(Clone, Debug, Default)]
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
    Typedef(TypeMap),
    Volatile(TypeMap),
    Const(TypeMap),
    Restrict(TypeMap),
    Function(Function),
    FunctionProto(FunctionProto),
    Variable(Variable),
    DataSection(DataSection),
    Float(Float),
    DeclTag(DeclTag),
    TypeTag(TypeMap),
    Enum64(Enum),
}

impl Type {
    /// Parses a single BTF type from the reader (advances the reader past the type).
    ///
    /// # Arguments
    /// * `reader` - The reader from which the integer is read.
    /// * `type_header` - The BTF type header that was read for this type.
    /// * `header` - The header associated with this type.
    fn from_reader<B: ByteOrder, R: Read + Seek + BufRead>(
        reader: &mut R,
        type_header: &TypeHeader,
        header: &Header<B>,
    ) -> Result<Self> {
        match type_header.get_kind()? {
            TypeKind::Void => Ok(Self::Void),
            TypeKind::Integer => Ok(Self::Integer(Integer::from_reader::<B, _>(
                reader,
                type_header,
            )?)),
            TypeKind::Pointer => Ok(Self::Pointer(TypeMap::from_type_header(type_header))),
            TypeKind::Array => Ok(Self::Array(Array::from_reader::<B, _>(reader)?)),
            TypeKind::Struct => Ok(Self::Struct(Struct::from_reader::<B, _>(
                reader,
                type_header,
                header,
            )?)),
            TypeKind::Union => Ok(Self::Struct(Struct::from_reader::<B, _>(
                reader,
                type_header,
                header,
            )?)),
            TypeKind::Enum32 => Ok(Self::Enum32(Enum::from_reader::<B, _>(
                reader,
                type_header,
                header,
            )?)),
            TypeKind::Fwd => Ok(Self::Fwd(Fwd::from_type_header(type_header))),
            TypeKind::Typedef => Ok(Self::Typedef(TypeMap::from_type_header(type_header))),
            TypeKind::Volatile => Ok(Self::Volatile(TypeMap::from_type_header(type_header))),
            TypeKind::Const => Ok(Self::Const(TypeMap::from_type_header(type_header))),
            TypeKind::Restrict => Ok(Self::Restrict(TypeMap::from_type_header(type_header))),
            TypeKind::Function => Ok(Self::Function(Function::from_type_header(type_header))),
            TypeKind::FunctionProto => Ok(Self::FunctionProto(FunctionProto::from_reader::<B, _>(
                reader,
                type_header,
                header,
            )?)),
            TypeKind::Variable => Ok(Self::Variable(Variable::from_reader::<B, _>(reader)?)),
            TypeKind::DataSection => Ok(Self::DataSection(DataSection::from_reader::<B, _>(
                reader,
                type_header,
            )?)),
            TypeKind::Float => Ok(Self::Float(Float::from_type_header(type_header))),
            TypeKind::DeclTag => Ok(Self::DeclTag(DeclTag::from_reader::<B, _>(reader)?)),
            TypeKind::TypeTag => Ok(Self::TypeTag(TypeMap::from_type_header(type_header))),
            TypeKind::Enum64 => Ok(Self::Enum64(Enum::from_reader::<B, _>(
                reader,
                type_header,
                header,
            )?)),
        }
    }
}

/// Represents a single parsed BTF type, that is, the common header and
/// type-specific information.
#[derive(Clone, Debug, Default)]
struct ParsedType {
    header: TypeHeader,
    ty: Type,
}

/// A type that's been resolved to its base type with attributes as fields.
#[derive(Clone, Debug, Default)]
pub struct FlattenedType {
    pub type_id: u32,
    pub bits: u32,
    pub base_type: Type,
    pub num_refs: u32,
    pub names: Vec<String>,
    pub tags: Vec<String>,
    pub is_volatile: bool,
    pub is_const: bool,
    pub is_restrict: bool,
    pub is_function: bool,
}

impl FlattenedType {
    const MAX_INDIRECTIONS: usize = 100;

    /// Helper for finding the total size of a parsed type.
    fn get_parsed_type_bits(types: &[ParsedType], id: u32, mut indirections: usize) -> Result<u32> {
        indirections += 1;
        if indirections == Self::MAX_INDIRECTIONS {
            return Err(Error::TypeLoop);
        }

        let flattened_type = Self::from_parsed_types(types, id)?;
        if flattened_type.num_refs > 0 {
            return Ok(64); // Treat all pointers as 64 bits for now.
        }

        let bits = match flattened_type.base_type {
            Type::Integer(t) => t.bits,
            Type::Array(t) => {
                let element_bits = Self::get_parsed_type_bits(types, t.elem_type_id, indirections)?;
                t.num_elements * element_bits
            }
            Type::Struct(t) | Type::Union(t) => {
                let mut bits = 0;
                for member in &t.members {
                    let member_bits =
                        Self::get_parsed_type_bits(types, member.type_id, indirections)?;
                    if member.offset + member_bits > bits {
                        bits = member.offset + member_bits;
                    }
                }
                bits
            }
            Type::Enum32(_) => 32,
            Type::Enum64(_) => 64,
            Type::DataSection(t) => {
                let mut bits = 0;
                for vars in &t.vars {
                    if vars.offset + vars.size * 8 > bits {
                        bits = vars.offset + vars.size * 8;
                    }
                }
                bits
            }
            Type::Void | Type::Fwd(_) | Type::FunctionProto(_) => 0,
            Type::Float(t) => t.bits,
            _ => {
                return Err(Error::InternalError {
                    message: "FlattenedType has non base type.",
                })
            }
        };

        Ok(bits)
    }

    /// Flattens a type by its type id. Since BTF types are chained together,
    /// the type info needs to be traversed to find the base type. This function
    /// traverses the function, starting at `id` and returns the base type.
    ///
    /// # Arguments
    ///
    /// * `types` - The array of parsed types where index is the type id.
    /// * `id` - The id of the type to flatten.
    fn from_parsed_types(types: &[ParsedType], id: u32) -> Result<Self> {
        let mut index: usize = id.try_into()?;
        let mut num_refs = 0;
        let mut names = vec![];
        let mut tags = vec![];
        let mut is_volatile = false;
        let mut is_const = false;
        let mut is_restrict = false;
        let mut is_function = false;
        let mut base_type: &Type;

        let mut i = 0;
        loop {
            // Prevent type loops.
            i += 1;
            if i == Self::MAX_INDIRECTIONS {
                return Err(Error::TypeLoop);
            }

            let ty = types.get(index).ok_or(Error::InvalidTypeIndex)?;
            base_type = &ty.ty;
            match base_type {
                Type::Integer(_)
                | Type::Struct(_)
                | Type::Union(_)
                | Type::Enum32(_)
                | Type::Enum64(_)
                | Type::Fwd(_)
                | Type::DataSection(_)
                | Type::Float(_) => {
                    if let Some(name) = &ty.header.name {
                        if i == 1 {
                            names.push(name.clone());
                        }
                    }
                    break;
                }
                Type::Pointer(t) => {
                    num_refs += 1;
                    index = t.type_id.try_into()?;
                }
                Type::Typedef(t) => {
                    if let Some(name) = &ty.header.name {
                        names.push(name.clone());
                    }
                    index = t.type_id.try_into()?;
                }
                Type::Volatile(t) => {
                    is_volatile = true;
                    index = t.type_id.try_into()?;
                }
                Type::Const(t) => {
                    is_const = true;
                    index = t.type_id.try_into()?;
                }
                Type::Restrict(t) => {
                    is_restrict = true;
                    index = t.type_id.try_into()?;
                }
                Type::Function(t) => {
                    if let Some(name) = &ty.header.name {
                        names.push(name.clone());
                    }
                    is_function = true;
                    index = t.type_id.try_into()?;
                }
                Type::TypeTag(t) => {
                    if let Some(name) = &ty.header.name {
                        tags.push(name.clone());
                    }
                    index = t.type_id.try_into()?;
                }
                _ => break,
            }
        }

        Ok(Self {
            type_id: id,
            bits: 0,
            base_type: base_type.clone(),
            num_refs,
            names,
            tags,
            is_volatile,
            is_const,
            is_restrict,
            is_function,
        })
    }
}

/// Represents a deserialized BTF file.
#[derive(Clone, Debug, Default)]
pub struct Btf {
    types: Vec<FlattenedType>,
    name_map: HashMap<String, u32>,
}

impl Btf {
    /// Reads the header using a specified endianess. This is called in `from_reader`
    /// after endianess has been determined.
    ///
    /// # Arguments
    ///
    /// * `reader` - A reader interface into the BTF data.
    fn inner_from_reader<B: ByteOrder, R: BufRead + Seek>(mut reader: R) -> Result<Self> {
        let header = Header::<B>::from_reader(&mut reader)?;
        let types = header.read_types(&mut reader)?;

        let mut name_map = HashMap::default();
        let mut flattened_types = vec![];
        for id in 0..types.len() {
            let index = id.try_into()?;
            let mut flattened_type = FlattenedType::from_parsed_types(&types, index)?;
            flattened_type.bits = FlattenedType::get_parsed_type_bits(&types, index, 0)?;
            for name in &flattened_type.names {
                name_map.insert(name.clone(), index);
            }
            flattened_types.push(flattened_type);
        }

        Ok(Btf {
            types: flattened_types,
            name_map,
        })
    }

    /// Parses a BTF file into a vector of types.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the BTF file.
    ///
    /// # Example
    /// ```
    /// use btf::btf::Btf;
    ///
    /// let btf = Btf::from_file("/sys/kernel/btf/vmlinux").expect("failed to parse btf");
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        /*
         * Arbitrary threshold of 50 MB to limit memory usage when parsing. If the
         * file is over 50MB the file is used to seek/parse, otherwise all data is
         * read into memory and then parsed. The latter is much quicker.
         */
        let meta = std::fs::metadata(&path)?;
        if meta.len() > 50 << 20 {
            let mut reader = BufReader::new(std::fs::File::open(&path)?);
            let magic = reader.read_u16::<LittleEndian>()?;
            match magic {
                0xeb9f => Self::inner_from_reader::<LittleEndian, _>(reader),
                0x9feb => Self::inner_from_reader::<BigEndian, _>(reader),
                _ => Err(Error::Parsing {
                    offset: reader.stream_position()?,
                    message: "Invalid magic value",
                }),
            }
        } else {
            let data = std::fs::read(path)?;
            let mut reader = Cursor::new(data);
            let magic = reader.read_u16::<LittleEndian>()?;
            match magic {
                0xeb9f => Self::inner_from_reader::<LittleEndian, _>(reader),
                0x9feb => Self::inner_from_reader::<BigEndian, _>(reader),
                _ => Err(Error::Parsing {
                    offset: reader.stream_position()?,
                    message: "Invalid magic value",
                }),
            }
        }
    }

    /// Returns a slice of the internal types.
    ///
    /// # Example
    /// ```
    /// use btf::btf::{Btf, FlattenedType};
    ///
    /// let btf = Btf::from_file("/sys/kernel/btf/vmlinux").expect("failed to parse btf");
    /// let types: Vec<&FlattenedType> = btf.get_types().iter().collect();
    /// assert!(types.len() > 0);
    /// ```
    pub fn get_types(&self) -> &[FlattenedType] {
        &self.types
    }

    /// Retrieves a type by its identifier.
    ///
    /// # Arguments
    ///
    /// * `id` - The id of the type to flatten.
    ///
    /// # Example
    /// ```
    /// use btf::btf::Btf;
    ///
    /// let btf = Btf::from_file("/sys/kernel/btf/vmlinux").expect("failed to parse btf");
    /// btf.get_type_by_id(0).expect("Type 0 not found");
    /// ```
    pub fn get_type_by_id(&self, id: u32) -> Result<&FlattenedType> {
        let index: usize = id.try_into()?;
        self.types.get(index).ok_or(Error::InvalidTypeIndex)
    }

    /// Retrieves a type by its name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    ///
    /// # Example
    /// ```
    /// use btf::btf::Btf;
    ///
    /// let btf = Btf::from_file("/sys/kernel/btf/vmlinux").expect("failed to parse btf");
    /// btf.get_type_by_name("task_struct").expect("task_struct not found");
    /// ```
    pub fn get_type_by_name(&self, name: &str) -> Result<&FlattenedType> {
        let index = *self.name_map.get(name).ok_or(Error::TypeNotFound)?;
        let index: usize = index.try_into()?;
        self.types.get(index).ok_or(Error::InvalidTypeIndex)
    }
}
