use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use glutin::context::PossiblyCurrentContext;
use glutin::display::Display;
use glutin::surface::{Surface, WindowSurface};
use snolc_ng::AppState;
use snolc_ng::ui::{UiAction, UiDraft};
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

enum UserEvent {
    Repaint(Duration),
}

struct DesktopApp {
    proxy: winit::event_loop::EventLoopProxy<UserEvent>,
    gl_window: Option<GlWindow>,
    gl: Option<Arc<glow::Context>>,
    egui: Option<egui_glow::EguiGlow>,
    state: AppState,
    draft: UiDraft,
}

impl DesktopApp {
    fn new(proxy: winit::event_loop::EventLoopProxy<UserEvent>) -> Self {
        Self {
            proxy,
            gl_window: None,
            gl: None,
            egui: None,
            state: AppState::default(),
            draft: UiDraft::default(),
        }
    }

    fn apply(&mut self, action: UiAction) {
        match action {
            UiAction::SetScreen(screen) => self.state.set_screen(screen),
            UiAction::Import(uri) => {
                let _ = self
                    .state
                    .import_profile(&uri, "manual import".into(), &BTreeSet::new());
            }
            UiAction::Select(index) => {
                let _ = self.state.select(index);
            }
            UiAction::ApprovePackage(package) => {
                let _ = self.state.approve_package(&package);
            }
            UiAction::Connect => {
                let _ = self.state.begin_connect();
            }
            UiAction::Disconnect => self.state.stopped("disconnected".into()),
            UiAction::Export => {
                if let Ok(profile) = self.state.selected_profile() {
                    self.draft.advanced_config = profile.profile.to_uri().unwrap_or_default();
                }
            }
        }
    }
}

impl winit::application::ApplicationHandler<UserEvent> for DesktopApp {
    fn resumed(&mut self, event_loop: &winit::event_loop::ActiveEventLoop) {
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
                    actions = snolc_ng::ui::render(ui, &self.state, &mut self.draft)
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
        if let Some(egui) = &mut self.egui {
            egui.destroy();
        }
    }
}

pub fn run() -> Result<(), String> {
    let event_loop = winit::event_loop::EventLoop::<UserEvent>::with_user_event()
        .build()
        .map_err(|error| error.to_string())?;
    let proxy = event_loop.create_proxy();
    event_loop
        .run_app(&mut DesktopApp::new(proxy))
        .map_err(|error| error.to_string())
}
