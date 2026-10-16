use rivetlua_core::{ObjectRef, Value};

use crate::{ObjectKind, Vm, VmError};

/// P10 可識別的封閉事件；Close 只保留名稱，不在本階段執行。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetamethodEvent {
    Index,
    NewIndex,
    Call,
    Add,
    Sub,
    Mul,
    Mod,
    Pow,
    Div,
    IDiv,
    Band,
    Bor,
    Bxor,
    Shl,
    Shr,
    Unm,
    Bnot,
    Lt,
    Le,
    Eq,
    Len,
    Concat,
    Close,
}

impl MetamethodEvent {
    pub const ALL: [Self; 23] = [
        Self::Index,
        Self::NewIndex,
        Self::Call,
        Self::Add,
        Self::Sub,
        Self::Mul,
        Self::Mod,
        Self::Pow,
        Self::Div,
        Self::IDiv,
        Self::Band,
        Self::Bor,
        Self::Bxor,
        Self::Shl,
        Self::Shr,
        Self::Unm,
        Self::Bnot,
        Self::Lt,
        Self::Le,
        Self::Eq,
        Self::Len,
        Self::Concat,
        Self::Close,
    ];

    pub const fn name_bytes(self) -> &'static [u8] {
        match self {
            Self::Index => b"__index",
            Self::NewIndex => b"__newindex",
            Self::Call => b"__call",
            Self::Add => b"__add",
            Self::Sub => b"__sub",
            Self::Mul => b"__mul",
            Self::Mod => b"__mod",
            Self::Pow => b"__pow",
            Self::Div => b"__div",
            Self::IDiv => b"__idiv",
            Self::Band => b"__band",
            Self::Bor => b"__bor",
            Self::Bxor => b"__bxor",
            Self::Shl => b"__shl",
            Self::Shr => b"__shr",
            Self::Unm => b"__unm",
            Self::Bnot => b"__bnot",
            Self::Lt => b"__lt",
            Self::Le => b"__le",
            Self::Eq => b"__eq",
            Self::Len => b"__len",
            Self::Concat => b"__concat",
            Self::Close => b"__close",
        }
    }
}

impl Vm {
    /// table、full userdata 與受控 file payload 有獨立 metatable；完整 ObjectId 每次重新驗證。
    pub fn get_metatable(&self, object: ObjectRef) -> Result<Option<ObjectRef>, VmError> {
        match self.object_kind(object)? {
            ObjectKind::Table => self.with_table(object, |table| table.metatable()),
            ObjectKind::Userdata => self.userdata_metatable(object),
            ObjectKind::File => self.with_file(object, |file| file.metatable),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub fn set_metatable(
        &mut self,
        object: ObjectRef,
        metatable: Option<ObjectRef>,
    ) -> Result<(), VmError> {
        let kind = self.object_kind(object)?;
        if !matches!(
            kind,
            ObjectKind::Table | ObjectKind::Userdata | ObjectKind::File
        ) {
            return Err(VmError::WrongObjectType);
        }
        let register = if let Some(reference) = metatable {
            self.with_table(reference, |table| table.finalizer_value() != Value::Nil)?
        } else {
            false
        };
        if register {
            self.preflight_finalizer_registration(object)?;
        }
        if let Some(reference) = metatable {
            if self.object_kind(reference)? != ObjectKind::Table {
                return Err(VmError::WrongObjectType);
            }
            self.write_ref(object, crate::gc::trace::RefField::Metatable, reference)?;
        }
        match kind {
            ObjectKind::Table => self.with_table_mut(object, |table, _ledger| {
                table.set_metatable(metatable);
                Ok(())
            })?,
            ObjectKind::Userdata => self.set_userdata_metatable(object, metatable)?,
            ObjectKind::File => self.with_file_mut(object, |file| file.metatable = metatable)?,
            _ => unreachable!("target kind 已驗證"),
        }
        if register {
            self.register_finalizer(object)?;
        }
        Ok(())
    }

    /// 只讀取 metatable 的 raw 欄位；本步不呼叫事件，也不建立缺席快取。
    pub fn lookup_metamethod(
        &mut self,
        object: ObjectRef,
        event: MetamethodEvent,
    ) -> Result<Value, VmError> {
        self.lookup_raw_metafield(object, event.name_bytes())
    }

    pub fn lookup_metamethod_value(
        &mut self,
        value: Value,
        event: MetamethodEvent,
    ) -> Result<Value, VmError> {
        self.lookup_raw_metafield_value(value, event.name_bytes())
    }

    /// 在既有 metatable 上 raw 查詢指定欄位；供 C auxiliary API 的 `__tostring`／`__name` 共用。
    pub fn lookup_raw_metafield(
        &mut self,
        object: ObjectRef,
        name: &[u8],
    ) -> Result<Value, VmError> {
        self.lookup_raw_metafield_value(Value::Object(object), name)
    }

    pub fn lookup_raw_metafield_value(
        &mut self,
        value: Value,
        name: &[u8],
    ) -> Result<Value, VmError> {
        let Some(metatable) = self.get_metatable_for_value(value)? else {
            return Ok(Value::Nil);
        };
        self.raw_get_byte_key(metatable, name)
    }
}

#[cfg(test)]
mod tests {
    use rivetlua_core::Value;

    use crate::{HostHandle, RootKind, Table, Vm, VmError};

    use super::MetamethodEvent;

    #[test]
    fn p10_1_event_lookup() {
        let names: &[(MetamethodEvent, &[u8])] = &[
            (MetamethodEvent::Index, b"__index"),
            (MetamethodEvent::NewIndex, b"__newindex"),
            (MetamethodEvent::Call, b"__call"),
            (MetamethodEvent::Add, b"__add"),
            (MetamethodEvent::Sub, b"__sub"),
            (MetamethodEvent::Mul, b"__mul"),
            (MetamethodEvent::Mod, b"__mod"),
            (MetamethodEvent::Pow, b"__pow"),
            (MetamethodEvent::Div, b"__div"),
            (MetamethodEvent::IDiv, b"__idiv"),
            (MetamethodEvent::Band, b"__band"),
            (MetamethodEvent::Bor, b"__bor"),
            (MetamethodEvent::Bxor, b"__bxor"),
            (MetamethodEvent::Shl, b"__shl"),
            (MetamethodEvent::Shr, b"__shr"),
            (MetamethodEvent::Unm, b"__unm"),
            (MetamethodEvent::Bnot, b"__bnot"),
            (MetamethodEvent::Lt, b"__lt"),
            (MetamethodEvent::Le, b"__le"),
            (MetamethodEvent::Eq, b"__eq"),
            (MetamethodEvent::Len, b"__len"),
            (MetamethodEvent::Concat, b"__concat"),
            (MetamethodEvent::Close, b"__close"),
        ];
        assert_eq!(MetamethodEvent::ALL.len(), names.len());
        for (event, name) in names {
            assert_eq!(event.name_bytes(), *name);
        }

        let mut vm = Vm::new().unwrap();
        let owner = vm.allocate_table().unwrap();
        let owner_handle = HostHandle::<Table>::new(&mut vm, owner).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let metatable_handle = HostHandle::<Table>::new(&mut vm, metatable).unwrap();
        assert_eq!(vm.get_metatable(owner), Ok(None));
        assert_eq!(
            vm.lookup_metamethod(owner, MetamethodEvent::Index),
            Ok(Value::Nil)
        );
        vm.set_metatable(owner, Some(metatable)).unwrap();
        assert_eq!(vm.get_metatable(owner), Ok(Some(metatable)));
        assert_eq!(
            vm.lookup_metamethod(owner, MetamethodEvent::Index),
            Ok(Value::Nil)
        );
        let metatable_of_metatable = vm.allocate_table().unwrap();
        let outer_handle = HostHandle::<Table>::new(&mut vm, metatable_of_metatable).unwrap();
        let fallback_key = vm.allocate_byte_string(b"__index").unwrap();
        let fallback_handle = HostHandle::<Value>::new(&mut vm, fallback_key).unwrap();
        vm.raw_set(
            metatable_of_metatable,
            Value::Object(fallback_key),
            Value::Boolean(true),
        )
        .unwrap();
        vm.set_metatable(metatable, Some(metatable_of_metatable))
            .unwrap();
        assert_eq!(
            vm.lookup_metamethod(owner, MetamethodEvent::Call),
            Ok(Value::Nil)
        );

        let key = vm.allocate_byte_string(b"__index").unwrap();
        let key_handle = HostHandle::<Value>::new(&mut vm, key).unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::Boolean(false))
            .unwrap();
        assert_eq!(
            vm.raw_get(metatable, Value::Object(key)),
            Ok(Value::Boolean(false))
        );
        assert_eq!(
            vm.lookup_metamethod(owner, MetamethodEvent::Index),
            Ok(Value::Boolean(false))
        );
        let event_value = vm.allocate_table().unwrap();
        let event_handle = HostHandle::<Table>::new(&mut vm, event_value).unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::Object(event_value))
            .unwrap();
        drop(event_handle);
        drop(key_handle);
        drop(fallback_handle);
        drop(outer_handle);
        drop(metatable_handle);
        vm.set_collect_every_allocation(true);
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(
            vm.lookup_metamethod(owner, MetamethodEvent::Index),
            Ok(Value::Object(event_value))
        );
        vm.allocate_table().unwrap();
        assert_eq!(vm.object_kind(event_value), Ok(crate::ObjectKind::Table));

        let before = vm.ledger_snapshot();
        let roots_before = vm.roots().total_count();
        vm.set_allocation_limit(before.committed);
        let limited = vm.ledger_snapshot();
        assert_eq!(
            vm.lookup_metamethod(owner, MetamethodEvent::Index),
            Ok(Value::Object(event_value))
        );
        assert_eq!(vm.ledger_snapshot(), limited);
        assert_eq!(vm.roots().total_count(), roots_before);
        assert_eq!(vm.allocate_byte_string(b"still-allocated"), Err(VmError::AllocationFailed));
        assert_eq!(vm.ledger_snapshot(), limited);
        vm.set_allocation_limit(before.limit);

        let mut foreign = Vm::new().unwrap();
        let foreign_table = foreign.allocate_table().unwrap();
        assert_eq!(
            vm.set_metatable(owner, Some(foreign_table)),
            Err(VmError::WrongVm)
        );
        let wrong_type = vm.allocate(Value::Integer(3)).unwrap();
        assert_eq!(
            vm.set_metatable(owner, Some(wrong_type)),
            Err(VmError::WrongObjectType)
        );
        assert_eq!(vm.get_metatable(owner), Ok(Some(metatable)));
        vm.set_metatable(owner, None).unwrap();
        assert_eq!(
            vm.lookup_metamethod(owner, MetamethodEvent::Index),
            Ok(Value::Nil)
        );
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(metatable), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(event_value), Err(VmError::StaleObject));
        drop(owner_handle);
        vm.collect().unwrap();
        assert_eq!(vm.roots().count(RootKind::Host), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p17_metamethod_lookup_uses_borrowed_key_without_lua_allocation() {
        let mut vm = Vm::new().unwrap();
        let owner = vm.allocate_table().unwrap();
        let _owner_root = HostHandle::<Table>::new(&mut vm, owner).unwrap();
        let metatable = vm.allocate_table().unwrap();
        vm.set_metatable(owner, Some(metatable)).unwrap();
        let outer = vm.allocate_table().unwrap();
        vm.set_metatable(metatable, Some(outer)).unwrap();
        let outer_index = vm.allocate_byte_string(b"__index").unwrap();
        vm.raw_set(outer, Value::Object(outer_index), Value::Boolean(true))
            .unwrap();

        let index = vm.allocate_byte_string(b"__index").unwrap();
        vm.raw_set(metatable, Value::Object(index), Value::Integer(17))
            .unwrap();
        let name = vm.allocate_byte_string(b"__name").unwrap();
        vm.raw_set(metatable, Value::Object(name), Value::Integer(23))
            .unwrap();
        let new_index = vm.allocate_byte_string(b"__newindex").unwrap();
        vm.raw_set(metatable, Value::Object(new_index), Value::Integer(37))
            .unwrap();
        let mut long_name = vec![b'x'; 80];
        long_name[9] = 0;
        long_name[10] = 0xff;
        let long_key = vm.allocate_byte_string(&long_name).unwrap();
        vm.raw_set(metatable, Value::Object(long_key), Value::Integer(41))
            .unwrap();
        let mut near_name = long_name.clone();
        near_name[79] = b'y';
        let dead = vm.allocate_byte_string(b"__call").unwrap();
        vm.raw_set(metatable, Value::Object(dead), Value::Integer(29))
            .unwrap();
        vm.raw_set(metatable, Value::Object(dead), Value::Nil)
            .unwrap();
        vm.raw_set(metatable, Value::Integer(7), Value::Integer(31))
            .unwrap();

        let roots = vm.roots().total_count();
        let before = vm.ledger_snapshot();
        vm.set_allocation_limit(before.committed);
        let limited = vm.ledger_snapshot();
        assert_eq!(
            vm.lookup_metamethod_value(Value::Object(owner), MetamethodEvent::Index),
            Ok(Value::Integer(17))
        );
        assert_eq!(
            vm.lookup_raw_metafield_value(Value::Object(owner), b"__name"),
            Ok(Value::Integer(23))
        );
        assert_eq!(
            vm.lookup_metamethod_value(Value::Object(owner), MetamethodEvent::NewIndex),
            Ok(Value::Integer(37))
        );
        assert_eq!(
            vm.lookup_raw_metafield_value(Value::Object(owner), &long_name),
            Ok(Value::Integer(41))
        );
        assert_eq!(
            vm.lookup_raw_metafield_value(Value::Object(owner), &near_name),
            Ok(Value::Nil)
        );
        for absent in [b"__call".as_slice(), b"__index_suffix", b"7"] {
            assert_eq!(
                vm.lookup_raw_metafield_value(Value::Object(owner), absent),
                Ok(Value::Nil)
            );
        }
        assert_eq!(vm.ledger_snapshot(), limited);
        assert_eq!(vm.roots().total_count(), roots);
        vm.set_allocation_limit(before.limit);
    }
}
