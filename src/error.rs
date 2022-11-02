use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error processing input")]
    Io(#[from] std::io::Error),

    #[error("error converting integer")]
    IntegerConversion(#[from] std::num::TryFromIntError),

    #[error("[offset: {offset:?}] {message:?}")]
    Parsing { offset: u64, message: &'static str },

    #[error("Unknown type ({type_num:?})")]
    UnknownType { type_num: u32 },

    #[error("Bad type index")]
    InvalidTypeIndex,

    #[error("Type loop detected")]
    TypeLoop,

    #[error("Type not found")]
    TypeNotFound,

    #[error("Type kind in enum is invalid")]
    InvalidEnumTypeKind,

    #[error("Variable linkage kind value was invalid")]
    InvalidLinkageKind,

    #[error("Internal Error: {message:?}")]
    InternalError { message: &'static str },
}

pub type Result<T> = std::result::Result<T, Error>;
