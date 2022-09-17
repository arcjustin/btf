use crate::types::*;

use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};

use std::collections::HashMap;
use std::fs::File;
use std::io::{
    BufRead, BufReader, Error, ErrorKind, Read, Seek, SeekFrom,
};
use std::slice::Iter;

#[derive(Debug)]
enum Endianess {
    Big,
    Little,
}

#[derive(Debug)]
struct BtfHeader {
    endianess: Endianess,
    _version: u8,
    _flags: u8,
    hdr_len: u32,

    /* all offsets are in bytes relative to the end of this header */
    type_off: u32,
    type_len: u32,
    str_off: u32,
    _str_len: u32,
}

impl BtfHeader {
    fn read_with_order<B: ByteOrder, R: Read>(
        reader: &mut R,
        endianess: Endianess,
    ) -> Result<Self, Error> {
        Ok(Self {
            endianess,
            _version: reader.read_u8()?,
            _flags: reader.read_u8()?,
            hdr_len: reader.read_u32::<B>()?,
            type_off: reader.read_u32::<B>()?,
            type_len: reader.read_u32::<B>()?,
            str_off: reader.read_u32::<B>()?,
            _str_len: reader.read_u32::<B>()?,
        })
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let magic = reader.read_u16::<LittleEndian>()?;
        match magic {
            0xeb9f => Self::read_with_order::<LittleEndian, _>(reader, Endianess::Little),
            0x9feb => Self::read_with_order::<BigEndian, _>(reader, Endianess::Big),
            _ => Err(Error::from(ErrorKind::InvalidData)),
        }
    }
}

#[derive(Debug, Default)]
struct BtfRawType {
    id: u32,
    name: String,
    info: u32,
    size_type: u32,
}

impl BtfRawType {
    fn read_with_order<B: ByteOrder, R: Read + Seek + BufRead>(
        id: u32,
        reader: &mut R,
        header: &BtfHeader,
    ) -> Result<Self, Error> {
        let name_off = reader.read_u32::<B>()?;
        let name = read_string(reader, header, name_off)?;
        let info = reader.read_u32::<B>()?;
        let size_type = reader.read_u32::<B>()?;

        Ok(Self {
            id,
            name,
            info,
            size_type,
        })
    }

    fn read<R: Read + Seek + BufRead>(
        id: u32,
        reader: &mut R,
        header: &BtfHeader,
    ) -> Result<Self, Error> {
        match header.endianess {
            Endianess::Little => Self::read_with_order::<LittleEndian, _>(id, reader, header),
            Endianess::Big => Self::read_with_order::<BigEndian, _>(id, reader, header),
        }
    }

    fn get_vlen(&self) -> u16 {
        self.info as u16
    }

    fn get_kind(&self) -> Result<TypeKind, Error> {
        let kind_val = (self.info >> 24) & 0x1f;
        match kind_val {
            0 => Ok(TypeKind::Void),
            1 => Ok(TypeKind::Integer),
            2 => Ok(TypeKind::Pointer),
            3 => Ok(TypeKind::Array),
            4 => Ok(TypeKind::Struct),
            5 => Ok(TypeKind::Union),
            6 => Ok(TypeKind::Enum32),
            7 => Ok(TypeKind::Fwd),
            8 => Ok(TypeKind::Typedef),
            9 => Ok(TypeKind::Volatile),
            10 => Ok(TypeKind::Const),
            11 => Ok(TypeKind::Restrict),
            12 => Ok(TypeKind::Function),
            13 => Ok(TypeKind::FunctionProto),
            14 => Ok(TypeKind::Variable),
            15 => Ok(TypeKind::DataSection),
            16 => Ok(TypeKind::Float),
            17 => Ok(TypeKind::DeclTag),
            18 => Ok(TypeKind::TypeTag),
            19 => Ok(TypeKind::Enum64),
            _ => Err(Error::from(ErrorKind::InvalidData)),
        }
    }

    fn get_kind_flag(&self) -> bool {
        ((self.info >> 31) & 0x1) == 0x1
    }

    fn get_type(&self) -> u32 {
        self.size_type
    }

    fn get_size(&self) -> u32 {
        self.size_type
    }
}

fn read_string<R: Read + Seek + BufRead>(
    reader: &mut R,
    header: &BtfHeader,
    offset: u32,
) -> Result<String, Error> {
    let oldpos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(
        header.hdr_len as u64 + header.str_off as u64 + offset as u64,
    ))?;

    let mut raw_str = vec![];
    reader.read_until(0, &mut raw_str)?;

    match std::str::from_utf8(&raw_str) {
        Ok(s) => {
            if s.is_empty() {
                return Err(Error::from(ErrorKind::InvalidData));
            }
            reader.seek(SeekFrom::Start(oldpos))?;
            Ok(String::from(&s[0..s.len() - 1]))
        }
        Err(_) => Err(Error::from(ErrorKind::InvalidData)),
    }
}

fn read_integer<B: ByteOrder, R: Read + Seek>(
    raw_type: &BtfRawType,
    reader: &mut R,
) -> Result<Type, Error> {
    let info = reader.read_u32::<B>()?;
    let name = raw_type.name.clone();
    let bits = info as u8;
    let is_signed = (info >> 24) & 0x1 == 0x1;
    let is_char = (info >> 24) & 0x2 == 0x2;
    let is_bool = (info >> 24) & 0x4 == 0x4;
    let offset = ((info >> 16) & 0xffff) as u16;
    Ok(Type::Integer(Integer {
        id: raw_type.id,
        name,
        size: raw_type.get_size(),
        bits,
        is_signed,
        is_char,
        is_bool,
        offset,
    }))
}

fn create_type_map(raw_type: &BtfRawType) -> TypeMap {
    TypeMap {
        id: raw_type.id,
        type_id: raw_type.get_type(),
    }
}

fn read_array<B: ByteOrder, R: Read + Seek>(
    raw_type: &BtfRawType,
    reader: &mut R,
) -> Result<Type, Error> {
    Ok(Type::Array(Array {
        id: raw_type.id,
        size: 0,
        element_type: reader.read_u32::<B>()?,
        index_type: reader.read_u32::<B>()?,
        num_elements: reader.read_u32::<B>()?,
    }))
}

fn read_struct_member<B: ByteOrder, R: Read + Seek + BufRead>(
    reader: &mut R,
    header: &BtfHeader,
) -> Result<StructMember, Error> {
    let name_off = reader.read_u32::<B>()?;
    let name = read_string(reader, header, name_off)?;
    let type_id = reader.read_u32::<B>()?;
    let bitfield_size_offset = reader.read_u32::<B>()?;

    Ok(StructMember {
        name,
        type_id,
        bitfield_size: bitfield_size_offset >> 24,
        offset: bitfield_size_offset & 0xffffff,
    })
}

fn read_struct<B: ByteOrder, R: Read + Seek + BufRead>(
    raw_type: &BtfRawType,
    reader: &mut R,
    header: &BtfHeader,
) -> Result<Type, Error> {
    let mut members = HashMap::<String, StructMember>::with_capacity(raw_type.get_vlen().into());
    for _ in 0..raw_type.get_vlen() {
        let member = read_struct_member::<B, _>(reader, header)?;
        members.insert(member.name.clone(), member);
    }

    Ok(Type::Struct(Struct {
        id: raw_type.id,
        name: raw_type.name.clone(),
        size: raw_type.get_size(),
        members,
    }))
}

fn read_union<B: ByteOrder, R: Read + Seek + BufRead>(
    raw_type: &BtfRawType,
    reader: &mut R,
    header: &BtfHeader,
) -> Result<Type, Error> {
    let num_members = raw_type.get_vlen() as usize;
    let mut members = HashMap::<String, StructMember>::with_capacity(num_members);
    for _ in 0..num_members {
        let member = read_struct_member::<B, _>(reader, header)?;
        members.insert(member.name.clone(), member);
    }

    Ok(Type::Union(Struct {
        id: raw_type.id,
        name: raw_type.name.clone(),
        size: raw_type.get_size(),
        members,
    }))
}

fn read_enum_entry<B: ByteOrder, R: Read + Seek + BufRead>(
    reader: &mut R,
    header: &BtfHeader,
    is_64b: bool,
) -> Result<EnumEntry, Error> {
    let name_off = reader.read_u32::<B>()?;
    let name = read_string(reader, header, name_off)?;
    let value = if is_64b {
        reader.read_i32::<B>()? as i64 | ((reader.read_i32::<B>()? as i64) << 32)
    } else {
        reader.read_i32::<B>()? as i64
    };

    Ok(EnumEntry { name, value })
}

fn read_enum<B: ByteOrder, R: Read + Seek + BufRead>(
    raw_type: &BtfRawType,
    reader: &mut R,
    header: &BtfHeader,
) -> Result<Type, Error> {
    let is_64b = match raw_type.get_kind() {
        Ok(TypeKind::Enum32) => false,
        Ok(TypeKind::Enum64) => true,
        _ => return Err(Error::from(ErrorKind::InvalidData)),
    };

    let mut entries = HashMap::<String, EnumEntry>::with_capacity(raw_type.get_vlen().into());
    for _ in 0..raw_type.get_vlen() {
        let entry = read_enum_entry::<B, _>(reader, header, is_64b)?;
        entries.insert(entry.name.clone(), entry);
    }

    if is_64b {
        Ok(Type::Enum64(Enum {
            id: raw_type.id,
            name: raw_type.name.clone(),
            size: (8 * raw_type.get_vlen()) as u32,
            entries,
        }))
    } else {
        Ok(Type::Enum32(Enum {
            id: raw_type.id,
            name: raw_type.name.clone(),
            size: (4 * raw_type.get_vlen()) as u32,
            entries,
        }))
    }
}

fn create_fwd(raw_type: &BtfRawType) -> Type {
    Type::Fwd(Fwd {
        id: raw_type.id,
        name: raw_type.name.clone(),
        is_union: raw_type.get_kind_flag(),
    })
}

fn create_typedef(raw_type: &BtfRawType) -> Type {
    Type::Typedef(Typedef {
        id: raw_type.id,
        name: raw_type.name.clone(),
        type_id: raw_type.get_type(),
    })
}

fn create_function(raw_type: &BtfRawType) -> Result<Type, Error> {
    let linkage = match raw_type.get_vlen() {
        0 => LinkageKind::Static,
        1 => LinkageKind::Global,
        _ => return Err(Error::from(ErrorKind::InvalidData)),
    };

    Ok(Type::Function(Function {
        id: raw_type.id,
        name: raw_type.name.clone(),
        linkage,
        type_id: raw_type.get_type(),
    }))
}

fn read_function_param<B: ByteOrder, R: Read + Seek + BufRead>(
    reader: &mut R,
    header: &BtfHeader,
) -> Result<FunctionParam, Error> {
    let name_off = reader.read_u32::<B>()?;
    let name = read_string(reader, header, name_off)?;
    let type_id = reader.read_u32::<B>()?;

    Ok(FunctionParam { name, type_id })
}

fn read_function_proto<B: ByteOrder, R: Read + Seek + BufRead>(
    raw_type: &BtfRawType,
    reader: &mut R,
    header: &BtfHeader,
) -> Result<Type, Error> {
    let mut params: Vec<FunctionParam> = vec![];
    for _ in 0..raw_type.get_vlen() {
        let param = read_function_param::<B, _>(reader, header)?;
        params.push(param);
    }

    Ok(Type::FunctionProto(FunctionProto {
        id: raw_type.id,
        params,
    }))
}

fn read_variable<B: ByteOrder, R: Read + Seek + BufRead>(
    raw_type: &BtfRawType,
    reader: &mut R,
) -> Result<Type, Error> {
    let linkage = match reader.read_u32::<B>()? {
        0 => LinkageKind::Static,
        1 => LinkageKind::Global,
        _ => return Err(Error::from(ErrorKind::InvalidData)),
    };

    Ok(Type::Variable(Variable {
        id: raw_type.id,
        name: raw_type.name.clone(),
        linkage,
    }))
}

fn read_section_info<B: ByteOrder, R: Read + Seek + BufRead>(
    raw_type: &BtfRawType,
    reader: &mut R,
) -> Result<SectionInfo, Error> {
    Ok(SectionInfo {
        id: raw_type.id,
        type_id: reader.read_u32::<B>()?,
        offset: reader.read_u32::<B>()?,
        size: reader.read_u32::<B>()?,
    })
}

fn read_data_section<B: ByteOrder, R: Read + Seek + BufRead>(
    raw_type: &BtfRawType,
    reader: &mut R,
) -> Result<Type, Error> {
    let mut sections: Vec<SectionInfo> = vec![];
    for _ in 0..raw_type.get_vlen() {
        let section = read_section_info::<B, _>(raw_type, reader)?;
        sections.push(section);
    }

    Ok(Type::DataSection(DataSection {
        id: raw_type.id,
        name: raw_type.name.clone(),
        sections,
    }))
}

fn create_float(raw_type: &BtfRawType) -> Type {
    Type::Float(Float {
        id: raw_type.id,
        name: raw_type.name.clone(),
        size: raw_type.get_size(),
    })
}

fn read_decl_tag<B: ByteOrder, R: Read + Seek + BufRead>(
    raw_type: &BtfRawType,
    reader: &mut R,
) -> Result<Type, Error> {
    Ok(Type::DeclTag(DeclTag {
        id: raw_type.id,
        name: raw_type.name.clone(),
        component_index: reader.read_u32::<B>()?,
    }))
}

fn create_type_tag(raw_type: &BtfRawType) -> Type {
    Type::TypeTag(TypeTag {
        id: raw_type.id,
        name: raw_type.name.clone(),
    })
}

pub struct BtfTypes {
    types: Vec<Type>,
    name_map: HashMap<String, u32>,
}

impl BtfTypes {
    fn read_with_order<B: ByteOrder, R: Read + Seek + BufRead>(
        reader: &mut R,
        header: &BtfHeader,
    ) -> Result<Self, Error> {
        let type_start = header.hdr_len as u64 + header.type_off as u64;
        let type_end = type_start + header.type_len as u64;
        reader.seek(SeekFrom::Start(type_start))?;

        let mut types = vec![Type::Void];
        let mut name_map = HashMap::new();

        loop {
            match reader.stream_position()? {
                n if n == type_end => break,
                n if n > type_end => return Err(Error::from(ErrorKind::InvalidData)),
                _ => (),
            }

            let id = types.len() as u32;
            let raw_type = BtfRawType::read(id, reader, header)?;
            let kind = raw_type.get_kind()?;

            let new_type = match kind {
                TypeKind::Void => return Err(Error::from(ErrorKind::InvalidData)),
                TypeKind::Integer => read_integer::<B, _>(&raw_type, reader)?,
                TypeKind::Pointer => Type::Pointer(create_type_map(&raw_type)),
                TypeKind::Array => read_array::<B, _>(&raw_type, reader)?,
                TypeKind::Struct => read_struct::<B, _>(&raw_type, reader, header)?,
                TypeKind::Union => read_union::<B, _>(&raw_type, reader, header)?,
                TypeKind::Enum32 => read_enum::<B, _>(&raw_type, reader, header)?,
                TypeKind::Fwd => create_fwd(&raw_type),
                TypeKind::Typedef => create_typedef(&raw_type),
                TypeKind::Volatile => Type::Volatile(create_type_map(&raw_type)),
                TypeKind::Const => Type::Const(create_type_map(&raw_type)),
                TypeKind::Restrict => Type::Restrict(create_type_map(&raw_type)),
                TypeKind::Function => create_function(&raw_type)?,
                TypeKind::FunctionProto => read_function_proto::<B, _>(&raw_type, reader, header)?,
                TypeKind::Variable => read_variable::<B, _>(&raw_type, reader)?,
                TypeKind::DataSection => read_data_section::<B, _>(&raw_type, reader)?,
                TypeKind::Float => create_float(&raw_type),
                TypeKind::DeclTag => read_decl_tag::<B, _>(&raw_type, reader)?,
                TypeKind::TypeTag => create_type_tag(&raw_type),
                TypeKind::Enum64 => read_enum::<B, _>(&raw_type, reader, header)?,
            };

            types.push(new_type);
            if !raw_type.name.is_empty() {
                name_map.insert(raw_type.name.clone(), id as u32);
            }
        }

        let mut btf = Self { types, name_map };

        /* resolve all array sizes */
        let mut array_sizes = HashMap::new();
        for t in &btf.types {
            if let Type::Array(a) = t {
                if let Some(qtype) = btf.resolve_type_by_id(a.element_type) {
                    let sz = qtype.get_size() * a.num_elements;
                    array_sizes.insert(a.id, sz);
                }
            }
        }

        for (id, sz) in &array_sizes {
            if let Some(Type::Array(a)) = btf.types.get_mut(*id as usize) {
                a.size = *sz;
            }
        }

        Ok(btf)
    }

    /// Parses a file containing raw BTF data and returns a BtfType database.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the BTF file.
    ///
    /// # Examples
    ///
    /// ```
    /// use btf::BtfTypes;
    ///
    /// let vmlinux_types = BtfTypes::from_file("resources/vmlinux");
    /// ```
    pub fn from_file(path: &str) -> Result<Self, Error> {
        let mut reader = match File::open(path) {
            Ok(file) => BufReader::new(file),
            Err(e) => return Err(e),
        };

        let header = match BtfHeader::read(&mut reader) {
            Ok(header) => header,
            Err(e) => return Err(e),
        };

        let r = match header.endianess {
            Endianess::Little => Self::read_with_order::<LittleEndian, _>(&mut reader, &header),
            Endianess::Big => Self::read_with_order::<BigEndian, _>(&mut reader, &header),
        };

        match r {
            Ok(s) => Ok(s),
            Err(e) => Err(e),
        }
    }

    /// Returns a type from a type identifier.
    ///
    /// # Arguments
    ///
    /// * `id` - The id of the type to search for.
    ///
    /// # Examples
    ///
    /// ```
    /// use btf::BtfTypes;
    ///
    /// let vmlinux_types = BtfTypes::from_file("resources/vmlinux").unwrap();
    /// let first_type = vmlinux_types.get_type_by_id(1).unwrap();
    /// ```
    pub fn get_type_by_id(&self, id: u32) -> Option<&Type> {
        if id as usize >= self.types.len() {
            None
        } else {
            Some(&self.types[id as usize])
        }
    }

    /// Returns a type given a name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type to search for.
    ///
    /// # Examples
    ///
    /// ```
    /// use btf::BtfTypes;
    ///
    /// let vmlinux_types = BtfTypes::from_file("resources/vmlinux").unwrap();
    /// let task_struct = vmlinux_types.get_type_by_name("task_struct").unwrap();
    /// ```
    pub fn get_type_by_name(&self, name: &str) -> Option<&Type> {
        match self.name_map.get(name) {
            Some(id) => self.get_type_by_id(*id),
            None => None,
        }
    }

    /// Returns an iterator that can be used to iterate all the types contained
    /// within the parsed BTF database.
    ///
    /// # Examples
    ///
    /// ```
    /// use btf::BtfTypes;
    ///
    /// let vmlinux_types = BtfTypes::from_file("resources/vmlinux").unwrap();
    /// for t in vmlinux_types.iter() {
    ///     println!("{:?}", t);
    /// }
    /// ```
    pub fn iter(&self) -> Iter<Type> {
        self.types.iter()
    }

    /// Returns a fully qualified type given the type identifier. Types that contain
    /// qualifiers or are pointers are represented as linked types, for example, a
    /// type that's a typedef to a pointer, like `typedef int *a;` could be represented
    /// as: `Typedef(id=1, tid=2) -> Pointer(id=2, tid=3) -> Integer(id=3, ...)`. this
    /// function flattens the link into a single type to make it easier for users.
    ///
    /// # Arguments
    ///
    /// * `id` - The id of the type to search for.
    ///
    /// # Examples
    ///
    /// ```
    /// use btf::BtfTypes;
    ///
    /// let vmlinux_types = BtfTypes::from_file("resources/vmlinux").unwrap();
    /// let first_type = vmlinux_types.resolve_type_by_id(1).unwrap();
    /// if first_type.is_volatile {
    ///     /* this type is volatile */
    /// }
    /// ```
    pub fn resolve_type_by_id(&self, mut type_id: u32) -> Option<QualifiedType> {
        let mut qualified_type = QualifiedType::default();

        loop {
            let btf_type = self.get_type_by_id(type_id)?;

            type_id = match btf_type {
                Type::Pointer(ptr) => {
                    qualified_type.num_refs += 1;
                    ptr.type_id
                }
                Type::Typedef(def) => {
                    qualified_type.is_typedef = true;
                    def.type_id
                }
                Type::Volatile(map) => {
                    qualified_type.is_volatile = true;
                    map.type_id
                }
                Type::Const(map) => {
                    qualified_type.is_constant = true;
                    map.type_id
                }
                Type::Restrict(map) => {
                    qualified_type.is_restrict = true;
                    map.type_id
                }
                Type::Function(func) => {
                    qualified_type.is_function = true;
                    func.type_id
                }
                _ => {
                    qualified_type.base_type = btf_type.clone();
                    return Some(qualified_type);
                }
            }
        }
    }

    /// Returns a fully qualified type given the type name. BTF represents types by
    /// linking various type ids together, for example, a type that's typedefed to a
    /// pointer, like `typedef int *a;` could be represented as:
    ///
    /// `Typedef(id=1, tid=2) -> Pointer(id=2, tid=3) -> Integer(id=3, ...)`.
    ///
    /// This function flattens the links into a single type to make it easier for users
    /// to work with.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type to search for.
    ///
    /// # Examples
    ///
    /// ```
    /// use btf::BtfTypes;
    /// use btf::types::Type;
    ///
    /// let vmlinux_types = BtfTypes::from_file("resources/vmlinux").unwrap();
    /// let execve = vmlinux_types.resolve_type_by_name("do_execve").unwrap();
    /// if let Type::FunctionProto(fp) = execve.base_type {
    ///     let param_type = vmlinux_types.resolve_type_by_id(fp.params[0].type_id).unwrap();
    ///     if param_type.is_pointer() && param_type.is_volatile {
    ///         /* the first parameter to do_execve is a volatile pointer */
    ///     }
    /// }
    /// ```
    pub fn resolve_type_by_name(&self, name: &str) -> Option<QualifiedType> {
        match self.name_map.get(name) {
            Some(id) => self.resolve_type_by_id(*id),
            None => None,
        }
    }
}
