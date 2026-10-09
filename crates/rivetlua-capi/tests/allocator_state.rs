use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::c_void;
use std::hash::{BuildHasherDefault, DefaultHasher};
use std::ptr;

#[cfg(feature = "lua55")]
use rivetlua_capi::luaL_alloc;
use rivetlua_capi::stack::{
    lua_State, lua_checkstack, lua_close, lua_createtable, lua_getallocf, lua_gettop, lua_newstate,
    lua_newuserdatauv, lua_pushinteger, lua_pushlstring, lua_rawseti, lua_setallocf, lua_settop,
    luaL_newstate,
};

type AllocCallback = unsafe extern "C" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void;
type MaybeAllocCallback = Option<AllocCallback>;
type BlockMap = HashMap<usize, Block, BuildHasherDefault<DefaultHasher>>;

const ALLOC_ALIGN: usize = std::mem::align_of::<u128>();

static BINDING_ONE: u8 = 0;
static BINDING_TWO: u8 = 0;

fn binding_one_ud() -> *mut c_void {
    (&BINDING_ONE as *const u8).cast_mut().cast()
}

fn binding_two_ud() -> *mut c_void {
    (&BINDING_TWO as *const u8).cast_mut().cast()
}

fn binding_id(ud: *mut c_void) -> Option<u8> {
    if ud == binding_one_ud() {
        Some(1)
    } else if ud == binding_two_ud() {
        Some(2)
    } else {
        None
    }
}

#[derive(Clone, Copy)]
struct Block {
    bytes: usize,
    first_binding: u8,
}

#[derive(Clone, Copy)]
struct Event {
    ordinal: usize,
    binding: u8,
    input: usize,
    osize: usize,
    nsize: usize,
    output: usize,
    token_origin: Option<u8>,
    injected_failure: bool,
    rejected: bool,
}

#[derive(Default)]
struct Tracker {
    events: Vec<Event>,
    blocks: BlockMap,
    fail_at: Option<usize>,
    successful_new: usize,
    successful_resize: usize,
    successful_free: usize,
    injected_failures: usize,
    unknown_pointer: usize,
    invalid_binding: usize,
    osize_mismatch: usize,
}

impl Tracker {
    fn clear(&mut self) {
        *self = Self::default();
    }
}

std::thread_local! {
    static TRACKER: RefCell<Tracker> = RefCell::new(Tracker::default());
    static CALLBACK_FAULT: Cell<bool> = const { Cell::new(false) };
    static REENTRY_STATE: Cell<*mut lua_State> = const { Cell::new(ptr::null_mut()) };
    static REENTRY_REJECTED: Cell<Option<bool>> = const { Cell::new(None) };
}

fn reset_tracker() {
    TRACKER.with(|tracker| tracker.borrow_mut().clear());
    CALLBACK_FAULT.with(|fault| fault.set(false));
    REENTRY_STATE.with(|state| state.set(ptr::null_mut()));
    REENTRY_REJECTED.with(|rejected| rejected.set(None));
}

fn with_tracker<R>(f: impl FnOnce(&Tracker) -> R) -> R {
    TRACKER.with(|tracker| f(&tracker.borrow()))
}

fn set_fail_at(ordinal: usize) {
    TRACKER.with(|tracker| tracker.borrow_mut().fail_at = Some(ordinal));
}

fn callback_faulted() -> bool {
    CALLBACK_FAULT.with(Cell::get)
}

fn mark_callback_fault() {
    let _ = CALLBACK_FAULT.try_with(|fault| fault.set(true));
}

#[cfg(feature = "lua54")]
fn create_state(allocator: MaybeAllocCallback, ud: *mut c_void) -> *mut lua_State {
    // SAFETY：allocator 與 ud 在 state 存活期間有效；測試 callback 不會重入 Lua、panic 或 longjmp。
    unsafe { lua_newstate(allocator, ud) }
}

#[cfg(feature = "lua55")]
fn create_state(allocator: MaybeAllocCallback, ud: *mut c_void) -> *mut lua_State {
    // SAFETY：allocator 與 ud 在 state 存活期間有效；測試 callback 不會重入 Lua、panic 或 longjmp。
    unsafe { lua_newstate(allocator, ud, 0) }
}

struct State(*mut lua_State);

impl State {
    fn new(allocator: MaybeAllocCallback, ud: *mut c_void) -> Self {
        Self(create_state(allocator, ud))
    }

    fn from_default_allocator() -> Self {
        // SAFETY：luaL_newstate 不接收外部 pointer；回傳 state 由此 guard 在同一執行緒關閉。
        Self(unsafe { luaL_newstate() })
    }

    fn as_ptr(&self) -> *mut lua_State {
        self.0
    }

    fn close(&mut self) {
        let state = std::mem::replace(&mut self.0, ptr::null_mut());
        if !state.is_null() {
            // SAFETY：state 由此 guard 建立，尚未關閉，且只由建立執行緒呼叫一次。
            unsafe { lua_close(state) };
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(feature = "lua55")]
unsafe fn raw_resize(ud: *mut c_void, ptr: *mut c_void, osize: usize, nsize: usize) -> *mut c_void {
    // SAFETY：ptr 是此 callback 先前由同一 luaL_alloc C allocator 配置的 block，或為 NULL；
    // nsize/osize 依 callback 追蹤的 block size 傳遞，free/realloc 各只執行一次。
    unsafe { luaL_alloc(ud, ptr, osize, nsize) }
}

#[cfg(feature = "lua54")]
unsafe fn raw_resize(
    _ud: *mut c_void,
    ptr: *mut c_void,
    osize: usize,
    nsize: usize,
) -> *mut c_void {
    if nsize == 0 {
        if !ptr.is_null() {
            let Ok(layout) = Layout::from_size_align(osize, ALLOC_ALIGN) else {
                return ptr::null_mut();
            };
            // SAFETY：追蹤器確認 ptr 是 System 成功配置且尚未釋放的 block，layout size 取自記錄。
            unsafe { System.dealloc(ptr.cast(), layout) };
        }
        return ptr::null_mut();
    }

    if ptr.is_null() {
        let Ok(layout) = Layout::from_size_align(nsize, ALLOC_ALIGN) else {
            return ptr::null_mut();
        };
        // SAFETY：layout 合法；回傳值為 System 配置器所擁有的新 block。
        return unsafe { System.alloc(layout) }.cast();
    }

    let Ok(layout) = Layout::from_size_align(osize, ALLOC_ALIGN) else {
        return ptr::null_mut();
    };
    // SAFETY：追蹤器確認 ptr 是 System block，osize 為其記錄大小；失敗時舊 block 仍有效。
    unsafe { System.realloc(ptr.cast(), layout, nsize) }.cast()
}

unsafe extern "C" fn tracking_allocator(
    ud: *mut c_void,
    ptr: *mut c_void,
    osize: usize,
    nsize: usize,
) -> *mut c_void {
    REENTRY_STATE.with(|state| {
        let active = state.replace(std::ptr::null_mut());
        if !active.is_null() {
            // SAFETY：state 由同一執行緒的測試 guard 持有；此同步重入必須在 CAPI
            // 驗證階段 fail-closed，不得再呼叫 allocator 或借用 VM。
            let rejected = unsafe {
                lua_checkstack(active, 1) == 0
                    && lua_getallocf(active, std::ptr::null_mut()).is_none()
            };
            REENTRY_REJECTED.with(|result| result.set(Some(rejected)));
        }
    });
    let result = TRACKER.try_with(|tracker| {
        let Ok(mut tracker) = tracker.try_borrow_mut() else {
            mark_callback_fault();
            return ptr::null_mut();
        };

        let Some(binding) = binding_id(ud) else {
            tracker.invalid_binding = tracker.invalid_binding.saturating_add(1);
            mark_callback_fault();
            return ptr::null_mut();
        };

        if tracker.events.try_reserve(1).is_err() {
            mark_callback_fault();
            return ptr::null_mut();
        }

        let Some(ordinal) = tracker.events.len().checked_add(1) else {
            mark_callback_fault();
            return ptr::null_mut();
        };
        let input = ptr.expose_provenance();
        let existing = if ptr.is_null() {
            None
        } else {
            tracker.blocks.get(&input).copied()
        };
        let mut rejected = false;
        let mut injected_failure = false;

        if !ptr.is_null() && existing.is_none() {
            tracker.unknown_pointer = tracker.unknown_pointer.saturating_add(1);
            mark_callback_fault();
            rejected = true;
        } else if let Some(block) = existing {
            if osize != block.bytes {
                tracker.osize_mismatch = tracker.osize_mismatch.saturating_add(1);
                mark_callback_fault();
            }
        }

        if !rejected && nsize != 0 && tracker.fail_at == Some(ordinal) {
            tracker.fail_at = None;
            tracker.injected_failures = tracker.injected_failures.saturating_add(1);
            injected_failure = true;
        }

        if !rejected && !injected_failure && nsize != 0 && tracker.blocks.try_reserve(1).is_err() {
            mark_callback_fault();
            rejected = true;
        }

        let output = if rejected || injected_failure {
            ptr::null_mut()
        } else {
            // SAFETY：新配置傳 NULL；realloc/free 僅傳入追蹤 map 中目前存活的 block。
            unsafe { raw_resize(ud, ptr, existing.map_or(osize, |block| block.bytes), nsize) }
        };

        if !rejected && !injected_failure {
            if nsize == 0 {
                if let Some(block) = existing {
                    tracker.blocks.remove(&input);
                    tracker.successful_free = tracker.successful_free.saturating_add(1);
                    let _ = block;
                }
            } else if !output.is_null() {
                if let Some(block) = existing {
                    tracker.blocks.remove(&input);
                    tracker.successful_resize = tracker.successful_resize.saturating_add(1);
                    tracker.blocks.insert(
                        output.expose_provenance(),
                        Block {
                            bytes: nsize,
                            first_binding: block.first_binding,
                        },
                    );
                } else {
                    tracker.successful_new = tracker.successful_new.saturating_add(1);
                    tracker.blocks.insert(
                        output.expose_provenance(),
                        Block {
                            bytes: nsize,
                            first_binding: binding,
                        },
                    );
                }
            }
        }

        tracker.events.push(Event {
            ordinal,
            binding,
            input,
            osize,
            nsize,
            output: output.expose_provenance(),
            token_origin: existing.map(|block| block.first_binding),
            injected_failure,
            rejected: rejected || (!injected_failure && nsize != 0 && output.is_null()),
        });
        output
    });

    match result {
        Ok(output) => output,
        Err(_) => {
            mark_callback_fault();
            ptr::null_mut()
        }
    }
}

fn assert_callback_invariants() {
    assert!(!callback_faulted(), "allocator callback 有未記錄的內部錯誤");
    with_tracker(|tracker| {
        assert_eq!(
            tracker.unknown_pointer, 0,
            "不得重複釋放或 resize 未知 token"
        );
        assert_eq!(
            tracker.invalid_binding, 0,
            "callback 必須收到有效的 binding ud"
        );
        assert_eq!(
            tracker.osize_mismatch, 0,
            "非 NULL token 的 osize 必須符合原配置大小"
        );

        for (index, event) in tracker.events.iter().enumerate() {
            assert_eq!(event.ordinal, index + 1, "callback ordinal 必須連續");
            if event.nsize == 0 {
                assert_eq!(event.output, 0, "nsize=0 必須回傳 NULL");
            } else if !event.injected_failure && !event.rejected {
                assert_ne!(event.output, 0, "成功的非零 admission 必須回傳 token");
            } else {
                assert_eq!(event.output, 0, "allocator 拒絕時不得回傳 token");
            }

            if event.input != 0 {
                assert!(
                    event.token_origin.is_some(),
                    "非 NULL ptr 必須是已追蹤 token"
                );
            }
        }
    });
}

#[test]
fn null_allocator_fails_without_callback_and_default_state_works() {
    reset_tracker();
    let failed = State::new(None, binding_one_ud());
    assert!(failed.as_ptr().is_null());
    with_tracker(|tracker| assert!(tracker.events.is_empty()));

    let mut default = State::from_default_allocator();
    assert!(!default.as_ptr().is_null());
    // SAFETY：default state 由此執行緒建立且仍存活，僅使用基本 stack API。
    unsafe {
        lua_pushinteger(default.as_ptr(), 73);
        assert_eq!(lua_gettop(default.as_ptr()), 1);
        lua_settop(default.as_ptr(), 0);
    }
    default.close();
    with_tracker(|tracker| assert!(tracker.events.is_empty()));
}

#[test]
fn custom_allocator_tracks_public_domains_and_close_releases_every_token_once() {
    reset_tracker();
    let mut state = State::new(Some(tracking_allocator), binding_one_ud());
    assert!(!state.as_ptr().is_null());
    let state_token = with_tracker(|tracker| {
        tracker
            .events
            .iter()
            .rev()
            .find(|event| event.nsize != 0 && event.input == 0 && event.output != 0)
            .map(|event| event.output)
            .expect("state 配置必須取得最後的非零 token")
    });

    let mut returned_ud = ptr::null_mut();
    // SAFETY：state 存活；returned_ud 為有效輸出 slot。
    let returned_allocator = unsafe { lua_getallocf(state.as_ptr(), &mut returned_ud) };
    let returned_allocator = returned_allocator.expect("getallocf 應回傳自訂 allocator");
    assert!(ptr::fn_addr_eq(
        returned_allocator,
        tracking_allocator as AllocCallback
    ));
    assert_eq!(returned_ud, binding_one_ud());

    // SAFETY：state 存活且同執行緒使用；每項操作只建立正常 Lua stack 值。
    unsafe {
        REENTRY_STATE.with(|slot| slot.set(state.as_ptr()));
        assert_eq!(lua_checkstack(state.as_ptr(), 256), 1);
        assert_eq!(REENTRY_REJECTED.with(Cell::get), Some(true));
        lua_createtable(state.as_ptr(), 8, 8);
        lua_pushinteger(state.as_ptr(), 41);
        lua_rawseti(state.as_ptr(), -2, 1);

        let string = vec![b's'; 4096];
        assert!(!lua_pushlstring(state.as_ptr(), string.as_ptr().cast(), string.len()).is_null());
        assert!(!lua_newuserdatauv(state.as_ptr(), 2048, 1).is_null());
    }

    with_tracker(|tracker| {
        assert!(
            !tracker.events.is_empty(),
            "state 與物件配置都須詢問 host allocator"
        );
        assert!(tracker.successful_new > 0, "須建立非 NULL admission token");
        assert!(tracker.events.iter().any(|event| event.nsize > 0));
    });
    assert_callback_invariants();

    state.close();
    with_tracker(|tracker| {
        assert!(
            tracker.blocks.is_empty(),
            "lua_close 必須釋放所有存活 token"
        );
        assert_eq!(
            tracker.successful_new, tracker.successful_free,
            "每個成功配置 token 必須恰好釋放一次"
        );
        assert_eq!(tracker.injected_failures, 0);
        let last = tracker.events.last().expect("close 必須退還 state token");
        assert_eq!((last.input, last.nsize), (state_token, 0));
    });
    assert_callback_invariants();
}

#[test]
fn rejected_admission_does_not_fallback_and_state_can_retry() {
    reset_tracker();
    let mut state = State::new(Some(tracking_allocator), binding_one_ud());
    assert!(!state.as_ptr().is_null());

    // SAFETY：state 由此執行緒建立且仍存活；lua_gettop 僅讀取目前 stack top。
    let top_before = unsafe { lua_gettop(state.as_ptr()) };
    let (next_ordinal, live_before, new_before) = with_tracker(|tracker| {
        (
            tracker.events.len() + 1,
            tracker.blocks.len(),
            tracker.successful_new,
        )
    });
    set_fail_at(next_ordinal);

    // SAFETY：state 存活且未關閉；userdata API 在 admission 失敗時應回傳 NULL 並保持 stack。
    let rejected = unsafe { lua_newuserdatauv(state.as_ptr(), 4096, 1) };
    assert!(
        rejected.is_null(),
        "NULL admission 不得以其他 allocator 完成操作"
    );
    // SAFETY：state 仍有效；讀取頂端可確認失敗操作未發布 userdata。
    assert_eq!(unsafe { lua_gettop(state.as_ptr()) }, top_before);
    with_tracker(|tracker| {
        assert_eq!(tracker.events.len(), next_ordinal);
        assert_eq!(tracker.injected_failures, 1);
        assert_eq!(tracker.blocks.len(), live_before);
        assert_eq!(tracker.successful_new, new_before);
        assert!(tracker.events.last().unwrap().injected_failure);
        assert!(tracker.events.last().unwrap().output == 0);
    });

    // SAFETY：同一 state 仍可用；移除測試注入點後重試同一種配置操作。
    let retried = unsafe { lua_newuserdatauv(state.as_ptr(), 4096, 1) };
    assert!(!retried.is_null(), "清除 failpoint 後 state 必須可重試");
    // SAFETY：只移除剛成功 push 的 userdata。
    unsafe { lua_settop(state.as_ptr(), top_before) };

    state.close();
    with_tracker(|tracker| {
        assert!(tracker.blocks.is_empty());
        assert_eq!(tracker.successful_new, tracker.successful_free);
        assert_eq!(tracker.injected_failures, 1);
    });
    assert_callback_invariants();
}

#[test]
fn setallocf_routes_new_tokens_and_old_token_frees_through_current_binding() {
    reset_tracker();
    let mut state = State::new(Some(tracking_allocator), binding_one_ud());
    assert!(!state.as_ptr().is_null());

    // SAFETY：state 存活；保留舊 binding 下建立的值，直到 allocator 已切換。
    unsafe {
        let old_string = b"allocator-state-old-binding";
        assert!(
            !lua_pushlstring(state.as_ptr(), old_string.as_ptr().cast(), old_string.len())
                .is_null()
        );
        lua_createtable(state.as_ptr(), 0, 8);
    }

    // SAFETY：state 存活；新 binding 只改變後續 callback 的目前 f/ud。
    unsafe { lua_setallocf(state.as_ptr(), Some(tracking_allocator), binding_two_ud()) };
    let mut returned_ud = ptr::null_mut();
    // SAFETY：state 存活；returned_ud 為有效輸出 slot。
    let current_allocator = unsafe { lua_getallocf(state.as_ptr(), &mut returned_ud) }
        .expect("getallocf 應回傳目前 allocator");
    assert!(ptr::fn_addr_eq(
        current_allocator,
        tracking_allocator as AllocCallback
    ));
    assert_eq!(returned_ud, binding_two_ud());

    // SAFETY：新 allocator 已安裝；新字串應由 binding two admission。
    unsafe {
        let new_string = vec![b'n'; 4096];
        assert!(
            !lua_pushlstring(state.as_ptr(), new_string.as_ptr().cast(), new_string.len())
                .is_null()
        );
    }

    state.close();
    with_tracker(|tracker| {
        assert!(tracker.blocks.is_empty());
        assert_eq!(tracker.successful_new, tracker.successful_free);
        assert!(
            tracker
                .events
                .iter()
                .any(|event| event.binding == 2 && event.nsize > 0),
            "切換後的新配置必須使用新的 ud"
        );
        assert!(
            tracker.events.iter().any(|event| {
                event.binding == 2 && event.nsize == 0 && event.token_origin == Some(1)
            }),
            "舊 binding 建立的 token 必須由目前的新 binding 釋放"
        );
    });
    assert_callback_invariants();
}
