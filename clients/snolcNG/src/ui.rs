use crate::{AppState, ConnectionState, Screen};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiAction {
    SetScreen(Screen),
    Import(String),
    Select(usize),
    ApprovePackage(String),
    Connect,
    Disconnect,
    Export,
}

#[derive(Default)]
pub struct UiDraft {
    pub import_uri: String,
    pub advanced_config: String,
}

pub fn render(ui: &mut egui::Ui, state: &AppState, draft: &mut UiDraft) -> Vec<UiAction> {
    let mut actions = Vec::new();
    egui::Panel::top("navigation").show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.heading("snolcNG");
            for (screen, label) in [
                (Screen::Profiles, "Profiles"),
                (Screen::Connection, "Connection"),
                (Screen::Advanced, "Advanced"),
            ] {
                if ui.selectable_label(state.screen == screen, label).clicked() {
                    actions.push(UiAction::SetScreen(screen));
                }
            }
        });
    });
    egui::CentralPanel::default().show(ui, |ui| match state.screen {
        Screen::Profiles => profiles(ui, state, draft, &mut actions),
        Screen::Connection => connection(ui, state, &mut actions),
        Screen::Advanced => advanced(ui, draft, &mut actions),
    });
    actions
}

fn profiles(ui: &mut egui::Ui, state: &AppState, draft: &mut UiDraft, actions: &mut Vec<UiAction>) {
    ui.heading("Profiles");
    ui.horizontal(|ui| {
        ui.text_edit_singleline(&mut draft.import_uri);
        if ui.button("Import").clicked() && !draft.import_uri.is_empty() {
            actions.push(UiAction::Import(std::mem::take(&mut draft.import_uri)));
        }
    });
    for (index, profile) in state.profiles.iter().enumerate() {
        ui.group(|ui| {
            if ui
                .selectable_label(state.selected == Some(index), &profile.profile.server_id)
                .clicked()
            {
                actions.push(UiAction::Select(index));
            }
            ui.label(format!("endpoint: {}", profile.profile.endpoint));
            ui.label(format!("source: {}", profile.source));
            for package in &profile.pending_packages {
                ui.horizontal(|ui| {
                    ui.label(format!("approval required: {package}"));
                    if ui.button("Approve").clicked() {
                        actions.push(UiAction::ApprovePackage(package.clone()));
                    }
                });
            }
        });
    }
}

fn connection(ui: &mut egui::Ui, state: &AppState, actions: &mut Vec<UiAction>) {
    ui.heading("Connection");
    ui.label(match &state.connection {
        ConnectionState::Disconnected => "disconnected".into(),
        ConnectionState::Connecting => "connecting".into(),
        ConnectionState::Connected => "connected".into(),
        ConnectionState::Denied(reason) => format!("denied: {reason}"),
        ConnectionState::Stopped(reason) => format!("stopped: {reason}"),
    });
    if matches!(state.connection, ConnectionState::Disconnected) {
        if ui.button("Connect").clicked() {
            actions.push(UiAction::Connect);
        }
    } else if ui.button("Disconnect").clicked() {
        actions.push(UiAction::Disconnect);
    }
    if let Some(status) = &state.status {
        ui.separator();
        ui.label(format!("used_bytes: {}", status.used_bytes));
        ui.label(format!(
            "limit_bytes: {}",
            status
                .limit_bytes
                .map_or_else(|| "unlimited".into(), |value| value.to_string())
        ));
        ui.label(format!(
            "rate: {}/{} B/s",
            status.upload_bytes_per_second.unwrap_or(0),
            status.download_bytes_per_second.unwrap_or(0)
        ));
        if let Some(expiration) = &status.expires_at {
            ui.label(format!("expires_at: {expiration}"));
        }
        if let Some(reason) = &status.reason {
            ui.label(format!("reason: {reason}"));
        }
        if status.stale {
            ui.colored_label(egui::Color32::YELLOW, "stale status");
        }
    }
}

fn advanced(ui: &mut egui::Ui, draft: &mut UiDraft, actions: &mut Vec<UiAction>) {
    ui.heading("Advanced");
    ui.add(
        egui::TextEdit::multiline(&mut draft.advanced_config)
            .code_editor()
            .desired_rows(24)
            .interactive(false),
    );
    if ui.button("Export profile").clicked() {
        actions.push(UiAction::Export);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_ui_completes_without_requesting_continuous_repaint() {
        let context = egui::Context::default();
        let mut draft = UiDraft::default();
        let mut repaint_delay = std::time::Duration::ZERO;
        for _ in 0..3 {
            let output = context.run_ui(egui::RawInput::default(), |ui| {
                assert!(render(ui, &AppState::default(), &mut draft).is_empty());
            });
            repaint_delay = output
                .viewport_output
                .get(&egui::ViewportId::ROOT)
                .unwrap()
                .repaint_delay;
            output.drop_without_applying_deltas();
        }
        assert_eq!(repaint_delay, std::time::Duration::MAX);
    }
}
