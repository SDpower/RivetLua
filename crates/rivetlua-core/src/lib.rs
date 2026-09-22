//! RivetLua 的值與數值核心。

#![forbid(unsafe_code)]

pub mod error;
pub mod limits;
pub mod number;
pub mod value;

pub use error::{CoreError, CoreErrorKind, Operation};
pub use number::{
    Number, add, bit_and, bit_not, bit_or, bit_xor, compare, divide, equal, floor_divide, modulo,
    multiply, negate, number_from_value, shift_left, shift_right, subtract,
};
pub use value::{ObjectRef, Value, ValueKind, select_and, select_or};

/// P00 骨架版本，不能當成 bytecode 或語言相容性版本。
pub const P00_SCAFFOLD_VERSION: &str = "0.0.0";
