//! Table 與字串索引共用的行程內雜湊器。

#[cfg(feature = "std")]
pub(crate) use std::collections::hash_map::DefaultHasher;

// no_std 沒有 DefaultHasher；只替換行程內 bucket 分布，不變更 bytecode wire。
#[cfg(not(feature = "std"))]
#[allow(deprecated)]
pub(crate) type DefaultHasher = core::hash::SipHasher;

#[allow(deprecated)]
pub(crate) fn new_default_hasher() -> DefaultHasher {
    DefaultHasher::new()
}
