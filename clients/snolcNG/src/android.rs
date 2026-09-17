use std::sync::{Mutex, OnceLock};
use std::{ffi::CStr, path::PathBuf};

use jni::objects::JObject;
use jni::{JValue, JavaVM, jni_sig, jni_str};
use winit::event_loop::EventLoopProxy;
use winit::platform::android::activity::AndroidApp;

use crate::native_ui::{NativeEvent, PlatformHooks, UserEvent};

static EVENT_PROXY: OnceLock<Mutex<Option<EventLoopProxy<UserEvent>>>> = OnceLock::new();

#[unsafe(no_mangle)]
fn android_main(app: AndroidApp) {
    let Some(root) = app.internal_data_path().map(|path| path.join("snolc")) else {
        return;
    };
    let Some(native_library_directory) = native_library_directory() else {
        return;
    };
    let request_app = app.clone();
    let protect_app = app.clone();
    let platform = PlatformHooks::android(
        native_library_directory,
        move || request_vpn(&request_app),
        move |socket| protect_socket(&protect_app, socket),
    );
    let _ = crate::native_ui::run_android(app, root, platform, |proxy| {
        let slot = EVENT_PROXY.get_or_init(|| Mutex::new(None));
        if let Ok(mut slot) = slot.lock() {
            *slot = Some(proxy);
        }
    });
}

fn native_library_directory() -> Option<PathBuf> {
    let mut information = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    let address = android_main as *const () as *const libc::c_void;
    // android's dynamic linker owns the returned path for the process lifetime.
    let found = unsafe { libc::dladdr(address, information.as_mut_ptr()) };
    if found == 0 {
        return None;
    }
    // dladdr initialized the structure after a nonzero result.
    let information = unsafe { information.assume_init() };
    if information.dli_fname.is_null() {
        return None;
    }
    // the linker returns a nul-terminated path.
    let path = unsafe { CStr::from_ptr(information.dli_fname) };
    PathBuf::from(path.to_str().ok()?)
        .parent()
        .map(PathBuf::from)
}

fn request_vpn(app: &AndroidApp) -> bool {
    with_activity(app, |env, activity| {
        env.call_method(activity, jni_str!("requestVpn"), jni_sig!("()Z"), &[])?
            .z()
    })
    .unwrap_or(false)
}

fn protect_socket(app: &AndroidApp, socket: i64) -> bool {
    let Ok(socket) = i32::try_from(socket) else {
        return false;
    };
    with_activity(app, |env, activity| {
        env.call_method(
            activity,
            jni_str!("protectSocket"),
            jni_sig!("(I)Z"),
            &[JValue::Int(socket)],
        )?
        .z()
    })
    .unwrap_or(false)
}

fn with_activity<T>(
    app: &AndroidApp,
    callback: impl FnOnce(&mut jni::Env<'_>, &JObject<'_>) -> jni::errors::Result<T>,
) -> jni::errors::Result<T> {
    let vm = unsafe { JavaVM::from_raw(app.vm_as_ptr().cast()) };
    let activity = app.activity_as_ptr() as jni::sys::jobject;
    vm.attach_current_thread(|env| {
        let activity = unsafe { env.as_cast_raw::<JObject>(&activity)? };
        callback(env, &activity)
    })
}

fn send(event: NativeEvent) {
    let Some(proxy) = EVENT_PROXY.get() else {
        return;
    };
    if let Ok(proxy) = proxy.lock()
        && let Some(proxy) = proxy.as_ref()
    {
        let _ = proxy.send_event(UserEvent::Platform(event));
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_owenewans_snolc_SnolcActivity_nativeVpnReady(
    _env: *mut jni::sys::JNIEnv,
    _class: jni::sys::jclass,
    fd: jni::sys::jint,
) {
    send(NativeEvent::VpnReady(fd));
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_owenewans_snolc_SnolcActivity_nativeVpnRevoked(
    _env: *mut jni::sys::JNIEnv,
    _class: jni::sys::jclass,
) {
    send(NativeEvent::VpnPermissionRevoked);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_owenewans_snolc_SnolcActivity_nativeNetworkChanged(
    _env: *mut jni::sys::JNIEnv,
    _class: jni::sys::jclass,
) {
    send(NativeEvent::NetworkChanged);
}
