use std::sync::{Mutex, OnceLock};
use std::{ffi::CStr, path::PathBuf};

use jni::objects::{JByteArray, JObject};
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
    let store_app = app.clone();
    let load_app = app.clone();
    let platform = PlatformHooks::android(
        native_library_directory,
        move || request_vpn(&request_app),
        move |socket| protect_socket(&protect_app, socket),
        move |server_id, credential| store_credential(&store_app, server_id, credential),
        move |server_id| load_credential(&load_app, server_id),
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

fn store_credential(app: &AndroidApp, server_id: &str, credential: &str) -> bool {
    with_activity(app, |env, activity| {
        let server_id = env.new_string(server_id)?;
        let credential = env.byte_array_from_slice(credential.as_bytes())?;
        env.call_method(
            activity,
            jni_str!("storeCredential"),
            jni_sig!("(Ljava/lang/String;[B)Z"),
            &[JValue::from(&server_id), JValue::from(&credential)],
        )?
        .z()
    })
    .unwrap_or(false)
}

fn load_credential(app: &AndroidApp, server_id: &str) -> Option<String> {
    with_activity(app, |env, activity| {
        let server_id = env.new_string(server_id)?;
        let output = env
            .call_method(
                activity,
                jni_str!("loadCredential"),
                jni_sig!("(Ljava/lang/String;)[B"),
                &[JValue::from(&server_id)],
            )?
            .l()?;
        if output.is_null() {
            return Ok(None);
        }
        let output = unsafe { JByteArray::from_raw(env, output.into_raw() as jni::sys::jarray) };
        let output = env.convert_byte_array(&output)?;
        Ok(String::from_utf8(output).ok())
    })
    .ok()
    .flatten()
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
