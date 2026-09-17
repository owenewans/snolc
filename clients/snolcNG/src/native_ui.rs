use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::runtime::{ClientEvent, EngineRuntime};
use crate::ui::{self, UiAction, UiDraft};
use crate::{
    AppState, ConnectionState, ModuleClass, Profile, ProvisionProfile, Secret,
    generate_client_config, persist_client_config,
};
use glutin::context::PossiblyCurrentContext;
use glutin::display::Display;
use glutin::surface::{Surface, WindowSurface};
use snolc::Lifecycle;
use winit::raw_window_handle::HasWindowHandle;

struct GlWindow {
    window: winit::window::Window,
    context: PossiblyCurrentContext,
    display: Display,
    surface: Surface<WindowSurface>,
}

impl GlWindow {
    unsafe fn new(event_loop: &winit::event_loop::ActiveEventLoop) -> Self {
        use glutin::context::NotCurrentGlContext;
        use glutin::display::{GetGlDisplay, GlDisplay};
        use glutin::prelude::GlSurface;

        let attributes = winit::window::WindowAttributes::default()
            .with_title("snolcNG")
            .with_inner_size(winit::dpi::LogicalSize::new(800.0, 600.0))
            .with_visible(false);
        let template = glutin::config::ConfigTemplateBuilder::new()
            .with_depth_size(0)
            .with_stencil_size(0)
            .with_transparency(false);
        let (mut window, config) = glutin_winit::DisplayBuilder::new()
            .with_preference(glutin_winit::ApiPreference::FallbackEgl)
            .with_window_attributes(Some(attributes.clone()))
            .build(event_loop, template, |mut configurations| {
                configurations.next().expect("OpenGL configuration")
            })
            .expect("OpenGL display");
        let display = config.display();
        let raw = window
            .as_ref()
            .map(|window| window.window_handle().expect("window handle").as_raw());
        let context_attributes = glutin::context::ContextAttributesBuilder::new().build(raw);
        let fallback = glutin::context::ContextAttributesBuilder::new()
            .with_context_api(glutin::context::ContextApi::Gles(None))
            .build(raw);
        let pending = unsafe {
            display
                .create_context(&config, &context_attributes)
                .or_else(|_| display.create_context(&config, &fallback))
                .expect("OpenGL context")
        };
        let window = window.take().unwrap_or_else(|| {
            glutin_winit::finalize_window(event_loop, attributes, &config).expect("window")
        });
        let size = window.inner_size();
        let surface_attributes = glutin::surface::SurfaceAttributesBuilder::<WindowSurface>::new()
            .build(
                window.window_handle().expect("window handle").as_raw(),
                NonZeroU32::new(size.width).unwrap_or(NonZeroU32::MIN),
                NonZeroU32::new(size.height).unwrap_or(NonZeroU32::MIN),
            );
        let surface = unsafe {
            display
                .create_window_surface(&config, &surface_attributes)
                .expect("OpenGL surface")
        };
        let context = pending.make_current(&surface).expect("current context");
        surface
            .set_swap_interval(
                &context,
                glutin::surface::SwapInterval::Wait(NonZeroU32::MIN),
            )
            .expect("swap interval");
        Self {
            window,
            context,
            display,
            surface,
        }
    }

    fn resize(&self, size: winit::dpi::PhysicalSize<u32>) {
        use glutin::surface::GlSurface;
        self.surface.resize(
            &self.context,
            NonZeroU32::new(size.width).unwrap_or(NonZeroU32::MIN),
            NonZeroU32::new(size.height).unwrap_or(NonZeroU32::MIN),
        );
    }

    fn swap(&self) {
        use glutin::surface::GlSurface;
        self.surface.swap_buffers(&self.context).expect("swap");
    }

    fn proc_address(&self, name: &std::ffi::CStr) -> *const std::ffi::c_void {
        use glutin::display::GlDisplay;
        self.display.get_proc_address(name)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NativeEvent {
    VpnReady(i32),
    VpnPermissionRevoked,
    NetworkChanged,
}

pub enum UserEvent {
    Repaint(Duration),
    Runtime,
    Platform(NativeEvent),
}

type StoreCredential = dyn Fn(&str, &str) -> bool + Send + Sync;
type LoadCredential = dyn Fn(&str) -> Option<String> + Send + Sync;

pub struct PlatformHooks {
    android: bool,
    request_vpn: Arc<dyn Fn() -> bool + Send + Sync>,
    protect_socket: Arc<dyn Fn(i64) -> bool + Send + Sync>,
    store_credential: Arc<StoreCredential>,
    load_credential: Arc<LoadCredential>,
    native_library_directory: Option<PathBuf>,
}

impl PlatformHooks {
    fn desktop() -> Self {
        Self {
            android: false,
            request_vpn: Arc::new(|| false),
            protect_socket: Arc::new(|_| true),
            store_credential: Arc::new(|_, _| true),
            load_credential: Arc::new(|_| None),
            native_library_directory: None,
        }
    }

    #[cfg(target_os = "android")]
    pub fn android(
        native_library_directory: PathBuf,
        request_vpn: impl Fn() -> bool + Send + Sync + 'static,
        protect_socket: impl Fn(i64) -> bool + Send + Sync + 'static,
        store_credential: impl Fn(&str, &str) -> bool + Send + Sync + 'static,
        load_credential: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            android: true,
            request_vpn: Arc::new(request_vpn),
            protect_socket: Arc::new(protect_socket),
            store_credential: Arc::new(store_credential),
            load_credential: Arc::new(load_credential),
            native_library_directory: Some(native_library_directory),
        }
    }
}

struct DesktopApp {
    proxy: winit::event_loop::EventLoopProxy<UserEvent>,
    gl_window: Option<GlWindow>,
    gl: Option<Arc<glow::Context>>,
    egui: Option<egui_glow::EguiGlow>,
    state: AppState,
    draft: UiDraft,
    root: PathBuf,
    runtime: EngineRuntime,
    platform: PlatformHooks,
    vpn_fd: Option<i32>,
}

impl DesktopApp {
    fn new(
        proxy: winit::event_loop::EventLoopProxy<UserEvent>,
        root: PathBuf,
        platform: PlatformHooks,
    ) -> Self {
        let runtime_proxy = proxy.clone();
        let protect_socket = Arc::clone(&platform.protect_socket);
        let mut application = Self {
            proxy,
            gl_window: None,
            gl: None,
            egui: None,
            state: AppState::default(),
            draft: UiDraft::default(),
            root,
            runtime: EngineRuntime::with_socket_protector(
                move || {
                    let _ = runtime_proxy.send_event(UserEvent::Runtime);
                },
                move |socket| protect_socket(socket),
            ),
            platform,
            vpn_fd: None,
        };
        application.restore_android_profiles();
        application
    }

    fn apply(&mut self, action: UiAction) {
        match action {
            UiAction::SetScreen(screen) => self.state.set_screen(screen),
            UiAction::Import(uri) => {
                if let Err(error) = self.import_profile(&uri) {
                    self.state.denied(error);
                }
            }
            UiAction::Select(index) => {
                let _ = self.state.select(index);
            }
            UiAction::ApprovePackage(package) => {
                let _ = self.state.approve_package(&package);
            }
            UiAction::Connect => {
                if let Err(error) = self.connect() {
                    self.state.denied(error);
                }
            }
            UiAction::Disconnect => {
                if let Err(error) = self.runtime.request_shutdown() {
                    self.state.stopped(error.to_string());
                }
            }
            UiAction::Export => {
                if let Ok(profile) = self.state.selected_profile() {
                    self.draft.advanced_config = profile.profile.to_uri().unwrap_or_default();
                }
            }
        }
    }

    fn connect(&mut self) -> Result<(), String> {
        self.state
            .begin_connect()
            .map_err(|error| error.to_string())?;
        let profile = self
            .state
            .selected_profile()
            .map_err(|error| error.to_string())?
            .profile
            .clone();
        if self.platform.android
            && profile.modules.iter().any(|module| {
                module.class == ModuleClass::Adapter
                    && module.package.starts_with("owenewans/adapter-tun@")
            })
            && self.vpn_fd.is_none()
        {
            if (self.platform.request_vpn)() {
                return Ok(());
            }
            return Err("VPN permission request failed".into());
        }
        self.start_profile(profile)
    }

    fn start_profile(&mut self, mut profile: Profile) -> Result<(), String> {
        if self.platform.android {
            let credential = (self.platform.load_credential)(&profile.server_id)
                .ok_or_else(|| "credential is unavailable in Android Keystore".to_owned())?;
            profile.credential = Secret::new(credential);
            profile.validate().map_err(|error| error.to_string())?;
        }
        if let Some(fd) = self.vpn_fd {
            for module in &mut profile.modules {
                if module.class == ModuleClass::Adapter
                    && module.package.starts_with("owenewans/adapter-tun@")
                {
                    module.options.insert("mode".into(), "android-fd".into());
                    module.options.insert("fd".into(), fd.into());
                    module.options.insert("mtu".into(), 1_280.into());
                    module
                        .options
                        .insert("packet_queue_bytes".into(), 262_144.into());
                }
            }
        }
        if let Some(directory) = &self.platform.native_library_directory {
            crate::install_bundled_modules(&profile, &self.root, directory)
                .map_err(|error| error.to_string())?;
        }
        let generated =
            generate_client_config(&profile, &self.root).map_err(|error| error.to_string())?;
        self.draft.advanced_config = generated.main_toml.clone();
        let path =
            persist_client_config(&generated, &self.root).map_err(|error| error.to_string())?;
        let cleanup = generated
            .files
            .iter()
            .filter(|file| file.secret)
            .map(|file| file.path.clone())
            .collect();
        self.runtime
            .start_with_cleanup(&path, cleanup)
            .map_err(|error| error.to_string())
    }

    fn import_profile(&mut self, uri: &str) -> Result<(), String> {
        let profile = Profile::from_uri(uri).map_err(|error| error.to_string())?;
        if self.platform.android {
            if self
                .state
                .profiles
                .iter()
                .any(|existing| existing.profile.server_id == profile.server_id)
            {
                return Err("server_id is already imported".into());
            }
            if !(self.platform.store_credential)(&profile.server_id, profile.credential.expose()) {
                return Err("Android Keystore rejected the credential".into());
            }
            let metadata = ProvisionProfile::from_profile(&profile);
            let contents = toml::to_string(&metadata).map_err(|error| error.to_string())?;
            let path = self
                .root
                .join("profiles")
                .join(format!("{}.toml", profile.server_id));
            crate::atomic_write(&path, contents.as_bytes()).map_err(|error| error.to_string())?;
        }
        self.state
            .import_profile(uri, "manual import".into(), &BTreeSet::new())
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn restore_android_profiles(&mut self) {
        if !self.platform.android {
            return;
        }
        let directory = self.root.join("profiles");
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten().take(crate::MAX_SUBSCRIPTION_PROFILES) {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(path) else {
                continue;
            };
            let Ok(metadata) = ProvisionProfile::parse_toml(&contents) else {
                continue;
            };
            let Some(credential) = (self.platform.load_credential)(&metadata.server_id) else {
                continue;
            };
            let Ok(profile) = metadata.with_secret(Secret::new(credential)) else {
                continue;
            };
            let Ok(uri) = profile.to_uri() else {
                continue;
            };
            let _ = self
                .state
                .import_profile(&uri, "Android Keystore".into(), &BTreeSet::new());
        }
    }

    fn platform_event(&mut self, event: NativeEvent) {
        match event {
            NativeEvent::VpnReady(fd) if fd >= 0 => {
                self.vpn_fd = Some(fd);
                let result = self
                    .state
                    .selected_profile()
                    .map(|profile| profile.profile.clone())
                    .map_err(|error| error.to_string())
                    .and_then(|profile| self.start_profile(profile));
                if let Err(error) = result {
                    self.state.stopped(error);
                }
            }
            NativeEvent::VpnReady(_) | NativeEvent::VpnPermissionRevoked => {
                self.vpn_fd = None;
                let _ = self
                    .runtime
                    .platform_event(snolc::PlatformEvent::VpnPermissionRevoked);
                self.state.stopped("VPN permission revoked".into());
            }
            NativeEvent::NetworkChanged => {
                let _ = self
                    .runtime
                    .platform_event(snolc::PlatformEvent::NetworkChanged);
            }
        }
    }

    fn drain_runtime(&mut self) {
        for event in self.runtime.drain() {
            match event {
                ClientEvent::Starting => {
                    self.state.connection = ConnectionState::Connecting;
                }
                ClientEvent::Ready => {}
                ClientEvent::Engine(snolc::Event::Lifecycle(Lifecycle::Running)) => {
                    self.state.connected();
                }
                ClientEvent::Engine(snolc::Event::Lifecycle(Lifecycle::Stopped))
                | ClientEvent::Stopped => self.state.stopped("engine stopped".into()),
                ClientEvent::Engine(snolc::Event::Lifecycle(Lifecycle::Failed)) => {
                    self.state.stopped("engine failed".into());
                }
                ClientEvent::Engine(snolc::Event::ModuleError { message, .. }) => {
                    self.state.stopped(message);
                }
                ClientEvent::Failed(error) => self.state.stopped(error),
                ClientEvent::Engine(_) => {}
            }
        }
        if self.state.take_repaint_request()
            && let Some(window) = &self.gl_window
        {
            window.window.request_redraw();
        }
    }
}

impl winit::application::ApplicationHandler<UserEvent> for DesktopApp {
    fn resumed(&mut self, event_loop: &winit::event_loop::ActiveEventLoop) {
        if self.gl_window.is_some() {
            return;
        }
        let gl_window = unsafe { GlWindow::new(event_loop) };
        let gl = unsafe {
            glow::Context::from_loader_function(|name| {
                let name = std::ffi::CString::new(name).expect("OpenGL symbol");
                gl_window.proc_address(&name)
            })
        };
        let gl = Arc::new(gl);
        let egui = egui_glow::EguiGlow::new(event_loop, Arc::clone(&gl), None, None, true);
        let proxy = self.proxy.clone();
        egui.egui_ctx.set_request_repaint_callback(move |request| {
            let _ = proxy.send_event(UserEvent::Repaint(request.delay));
        });
        gl_window.window.set_visible(true);
        gl_window.window.request_redraw();
        self.gl_window = Some(gl_window);
        self.gl = Some(gl);
        self.egui = Some(egui);
    }

    fn suspended(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop) {
        if let Some(mut egui) = self.egui.take() {
            egui.destroy();
        }
        self.gl.take();
        self.gl_window.take();
    }

    fn window_event(
        &mut self,
        event_loop: &winit::event_loop::ActiveEventLoop,
        _window_id: winit::window::WindowId,
        event: winit::event::WindowEvent,
    ) {
        use winit::event::WindowEvent;
        if matches!(event, WindowEvent::CloseRequested | WindowEvent::Destroyed) {
            event_loop.exit();
            return;
        }
        if let WindowEvent::Resized(size) = event {
            self.gl_window.as_ref().unwrap().resize(size);
        }
        if matches!(event, WindowEvent::RedrawRequested) {
            let mut actions = Vec::new();
            self.egui
                .as_mut()
                .unwrap()
                .run(&self.gl_window.as_ref().unwrap().window, |ui| {
                    actions = ui::render(ui, &self.state, &mut self.draft)
                });
            for action in actions {
                self.apply(action);
            }
            unsafe {
                use glow::HasContext;
                self.gl.as_ref().unwrap().clear_color(0.06, 0.07, 0.08, 1.0);
                self.gl.as_ref().unwrap().clear(glow::COLOR_BUFFER_BIT);
            }
            self.egui
                .as_mut()
                .unwrap()
                .paint(&self.gl_window.as_ref().unwrap().window);
            self.gl_window.as_ref().unwrap().swap();
            event_loop.set_control_flow(winit::event_loop::ControlFlow::Wait);
            return;
        }
        let response = self
            .egui
            .as_mut()
            .unwrap()
            .on_window_event(&self.gl_window.as_ref().unwrap().window, &event);
        if response.repaint {
            self.gl_window.as_ref().unwrap().window.request_redraw();
        }
    }

    fn user_event(&mut self, event_loop: &winit::event_loop::ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Repaint(delay) if delay.is_zero() => {
                if let Some(window) = &self.gl_window {
                    window.window.request_redraw();
                }
                event_loop.set_control_flow(winit::event_loop::ControlFlow::Wait);
            }
            UserEvent::Repaint(delay) => {
                event_loop.set_control_flow(
                    Instant::now()
                        .checked_add(delay)
                        .map_or(winit::event_loop::ControlFlow::Wait, |deadline| {
                            winit::event_loop::ControlFlow::WaitUntil(deadline)
                        }),
                );
            }
            UserEvent::Runtime => self.drain_runtime(),
            UserEvent::Platform(event) => self.platform_event(event),
        }
    }

    fn new_events(
        &mut self,
        _event_loop: &winit::event_loop::ActiveEventLoop,
        cause: winit::event::StartCause,
    ) {
        if matches!(cause, winit::event::StartCause::ResumeTimeReached { .. })
            && let Some(window) = &self.gl_window
        {
            window.window.request_redraw();
        }
    }

    fn exiting(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop) {
        let _ = self.runtime.request_shutdown();
        if let Some(egui) = &mut self.egui {
            egui.destroy();
        }
    }
}

pub fn run_desktop(root: PathBuf) -> Result<(), String> {
    let event_loop = winit::event_loop::EventLoop::<UserEvent>::with_user_event()
        .build()
        .map_err(|error| error.to_string())?;
    let proxy = event_loop.create_proxy();
    event_loop
        .run_app(&mut DesktopApp::new(proxy, root, PlatformHooks::desktop()))
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "android")]
pub fn run_android(
    app: winit::platform::android::activity::AndroidApp,
    root: PathBuf,
    platform: PlatformHooks,
    register_proxy: impl FnOnce(winit::event_loop::EventLoopProxy<UserEvent>),
) -> Result<(), String> {
    use winit::platform::android::EventLoopBuilderExtAndroid;

    let mut builder = winit::event_loop::EventLoop::<UserEvent>::with_user_event();
    builder.with_android_app(app);
    let event_loop = builder.build().map_err(|error| error.to_string())?;
    let proxy = event_loop.create_proxy();
    register_proxy(proxy.clone());
    event_loop
        .run_app(&mut DesktopApp::new(proxy, root, platform))
        .map_err(|error| error.to_string())
}
