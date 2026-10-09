//! P16-3A1 私有 C-only checkpoint 入口；C callback 與公開 Lua error API 留待 A2。

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::error::{ErrorClass, Reject, codes};
use crate::stack::lua_State;

#[derive(Clone, Copy, Debug)]
pub struct Checkpoint {
    pub state: *mut lua_State,
    pub generation: u64,
    pub token: u64,
}

impl Checkpoint {
    pub fn with_state(self, state: *mut lua_State) -> Self {
        Self { state, ..self }
    }

    pub fn with_generation(self, generation: u64) -> Self {
        Self { generation, ..self }
    }

    pub fn with_token(self, token: u64) -> Self {
        Self { token, ..self }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Return(i32),
    Raise(ErrorClass),
    Reject(Reject),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Normal(i32),
    Raised(ErrorClass),
    Rejected(Reject),
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawAction {
    kind: i32,
    value: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawOutcome {
    kind: i32,
    value: i32,
}

type ActionFn = unsafe extern "C" fn(*mut c_void, u64, u64, *mut c_void) -> RawAction;

unsafe extern "C" {
    fn rivetlua_capi_trampoline_probe_a1(state: *mut c_void, generation: u64, token: u64) -> i32;
    fn rivetlua_capi_rust_action_enter_a1(state: *mut c_void, generation: u64, token: u64) -> i32;
    fn rivetlua_capi_rust_action_exit_a1(state: *mut c_void, generation: u64, token: u64) -> i32;
    fn rivetlua_capi_trampoline_protect_a1(
        state: *mut c_void,
        action_fn: ActionFn,
        context: *mut c_void,
    ) -> RawOutcome;
}

fn encode_action(action: Action) -> RawAction {
    match action {
        Action::Return(value) => RawAction {
            kind: codes::ACTION_RETURN,
            value,
        },
        Action::Raise(class) => RawAction {
            kind: codes::ACTION_RAISE,
            value: class as i32,
        },
        Action::Reject(reject) => RawAction {
            kind: codes::ACTION_REJECT,
            value: reject as i32,
        },
    }
}

/// C facade 僅取得 POD action；任何跳轉都由本函式完全返回後的 C frame 執行。
///
/// # Safety
/// mismatch 時非空 state 必須在呼叫期間有效；C wrapper 保證同步使用與無 foreign unwind。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_checkversion_prepare_a48(
    state: *mut c_void,
    generation: u64,
    token: u64,
    version: f64,
    sizes: usize,
) -> RawAction {
    let action = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：有效 state 是 C facade 的 mismatch 前置條件；helper 驗證 checkpoint 身分。
        unsafe {
            crate::error::prepare_checkversion(
                Checkpoint {
                    state: state.cast(),
                    generation,
                    token,
                },
                version,
                sizes,
            )
        }
    }))
    .unwrap_or(Action::Reject(Reject::Panic));
    encode_action(action)
}

const _: () = {
    assert!(std::mem::size_of::<RawAction>() == 2 * std::mem::size_of::<i32>());
    assert!(std::mem::size_of::<RawOutcome>() == 2 * std::mem::size_of::<i32>());
    assert!(codes::ACTION_RETURN != codes::ACTION_RAISE);
    assert!(codes::OUT_NORMAL != codes::OUT_RAISED);
};

pub fn probe(checkpoint: Checkpoint) -> Result<(), Reject> {
    // SAFETY：C probe 僅比較 pointer 與整數，不解參照 state，也不跳轉。
    let code = unsafe {
        rivetlua_capi_trampoline_probe_a1(
            checkpoint.state.cast(),
            checkpoint.generation,
            checkpoint.token,
        )
    };
    if code == codes::OK {
        Ok(())
    } else {
        Err(Reject::from_code(code))
    }
}

unsafe extern "C" fn action_bridge<F>(
    state: *mut c_void,
    generation: u64,
    token: u64,
    context: *mut c_void,
) -> RawAction
where
    F: FnOnce(Checkpoint) -> Action,
{
    // SAFETY：C top 持有這組精確身分；此 guard 阻止 C facade 跳過目前 Rust action frame。
    let entered = unsafe { rivetlua_capi_rust_action_enter_a1(state, generation, token) };
    if entered != codes::OK {
        return encode_action(Action::Reject(Reject::from_code(entered)));
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：context 只由 protect 借出，指向其尚存活的 Option<F>；C 同步且只呼叫一次。
        let action = unsafe { &mut *context.cast::<Option<F>>() }.take();
        let Some(action) = action else {
            return Action::Reject(Reject::InvalidAction);
        };
        action(Checkpoint {
            state: state.cast(),
            generation,
            token,
        })
    }));
    // SAFETY：Rust closure（含 Drop 與 panic 捕捉）已結束；只清除同一 C top 的 guard。
    let exited = unsafe { rivetlua_capi_rust_action_exit_a1(state, generation, token) };
    let action = if exited == codes::OK {
        result.unwrap_or(Action::Reject(Reject::Panic))
    } else {
        Action::Reject(Reject::from_code(exited))
    };
    encode_action(action)
}

/// 由 Rust 進入 C checkpoint；C 等 Rust action 完整返回後才可能跳轉。
///
/// # Safety
/// 非空 state 必須在整個同步呼叫期間有效，不能在 callback 中釋放；私有入口檢查
/// state 身分、執行緒與 borrow。action 不得讓 foreign unwind 越過 ABI。
pub unsafe fn protect<F>(state: *mut lua_State, action: F) -> Outcome
where
    F: FnOnce(Checkpoint) -> Action,
{
    let mut action = Some(action);
    // SAFETY：action 的 Option 位於此 Rust frame，C 在返回前只同步呼叫 bridge 一次；
    // C 的跳轉起訖都在 trampoline_protect 自身 frame，Rust bridge 已返回且 Drop 已完成。
    let raw = unsafe {
        rivetlua_capi_trampoline_protect_a1(
            state.cast(),
            action_bridge::<F>,
            (&mut action as *mut Option<F>).cast(),
        )
    };
    match raw.kind {
        codes::OUT_NORMAL => Outcome::Normal(raw.value),
        codes::OUT_RAISED => match ErrorClass::from_code(raw.value) {
            Some(class) => Outcome::Raised(class),
            None => Outcome::Rejected(Reject::InvalidAction),
        },
        codes::OUT_REJECTED => Outcome::Rejected(Reject::from_code(raw.value)),
        _ => Outcome::Rejected(Reject::InvalidAction),
    }
}
