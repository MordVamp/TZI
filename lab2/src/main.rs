mod crypto;
mod fingerprint;
mod license;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use egui::*;
use std::path::PathBuf;

use crypto::{derive_key, encrypt, decrypt};
use fingerprint::{compute_fingerprint, fingerprint_params};
use license::{generate_key, save_license, verify_key, MASTER_SECRET};

fn main() -> eframe::Result {
    let opts = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_title("ПАСЗИ — Лабораторная работа №2 — DRM система")
            .with_inner_size([860.0, 580.0]),
        ..Default::default()
    };
    eframe::run_native("lab2", opts, Box::new(|cc| Ok(Box::new(Lab2App::new(cc)))))
}

// ─── Вкладки ─────────────────────────────────────────────────────────────────
#[derive(PartialEq)]
enum Tab { Encrypt, Decrypt, License, Fingerprint }

struct Lab2App {
    tab: Tab,
    // Шифрование
    enc_path: String,
    enc_password: String,
    enc_status: String,
    // Расшифровка
    dec_path: String,
    dec_password: String,
    dec_key: String,        // лицензионный ключ
    dec_content: String,
    dec_status: String,
    dec_use_license: bool,  // true = по лицензии, false = по паролю
    // Менеджер лицензий
    lic_filename: String,
    lic_generated_key: String,
    lic_status: String,
    // Отпечаток
    fp_params: Vec<(String, String)>,
    fp_hash: String,
}

impl Lab2App {
    fn new(_cc: &eframe::CreationContext) -> Self {
        let fp_params = fingerprint_params();
        let fp_hash = compute_fingerprint();
        Self {
            tab: Tab::Encrypt,
            enc_path: String::new(), enc_password: String::new(), enc_status: String::new(),
            dec_path: String::new(), dec_password: String::new(), dec_key: String::new(),
            dec_content: String::new(), dec_status: String::new(), dec_use_license: false,
            lic_filename: String::new(), lic_generated_key: String::new(), lic_status: String::new(),
            fp_params, fp_hash,
        }
    }

    fn do_encrypt(&mut self) {
        let path = PathBuf::from(self.enc_path.trim());
        if !path.exists() { self.enc_status = "❌ Файл не найден.".into(); return; }

        let data = match std::fs::read(&path) {
            Ok(d) => d, Err(e) => { self.enc_status = format!("❌ {}", e); return; }
        };

        let key = derive_key(&self.enc_password);
        let ct = encrypt(&data, &key);
        let encoded = B64.encode(&ct);

        let out_path = path.with_extension(
            format!("{}.drm", path.extension().and_then(|e| e.to_str()).unwrap_or(""))
        );
        match std::fs::write(&out_path, encoded.as_bytes()) {
            Ok(_) => {
                // Сгенерировать и сохранить лицензию
                let fname = out_path.file_name().unwrap().to_string_lossy().to_string();
                let lkey = generate_key(&fname);
                let _ = save_license(&fname, &lkey);
                self.enc_status = format!(
                    "✅ Зашифровано → {}\n🔑 Лицензионный ключ: {}",
                    out_path.display(), lkey
                );
            }
            Err(e) => { self.enc_status = format!("❌ {}", e); }
        }
    }

    fn do_decrypt(&mut self) {
        let path = PathBuf::from(self.dec_path.trim());
        if !path.exists() { self.dec_status = "❌ Файл не найден.".into(); return; }

        let fname = path.file_name().unwrap().to_string_lossy().to_string();

        // Проверка лицензии или пароля
        if self.dec_use_license {
            let key_input = self.dec_key.trim().to_string();
            if !verify_key(&fname, &key_input) {
                self.dec_status = "❌ Лицензионный ключ недействителен для данного файла/компьютера.".into();
                return;
            }
            // Пароль выводим из ключа
            self.dec_password = format!("{}|{}", MASTER_SECRET, key_input);
        }

        let raw = match std::fs::read(&path) {
            Ok(d) => d, Err(e) => { self.dec_status = format!("❌ {}", e); return; }
        };

        let ct = match B64.decode(&raw) {
            Ok(d) => d,
            Err(_) => { self.dec_status = "❌ Файл не является DRM-файлом (ошибка base64).".into(); return; }
        };

        let key = derive_key(&self.dec_password);
        match decrypt(&ct, &key) {
            Some(plain) => {
                self.dec_content = String::from_utf8_lossy(&plain).to_string();
                self.dec_status = "✅ Файл успешно расшифрован.".into();
            }
            None => {
                self.dec_status = "❌ Неверный пароль или файл повреждён.".into();
                self.dec_content.clear();
            }
        }
    }
}

impl eframe::App for Lab2App {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(Visuals::dark());

        TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Encrypt, "🔒 Шифрование");
                ui.selectable_value(&mut self.tab, Tab::Decrypt, "🔓 Просмотрщик");
                ui.selectable_value(&mut self.tab, Tab::License, "🗝 Лицензии");
                ui.selectable_value(&mut self.tab, Tab::Fingerprint, "💻 Отпечаток");
            });
        });

        CentralPanel::default().show(ctx, |ui| {
            match self.tab {
                Tab::Encrypt    => self.show_encrypt(ui),
                Tab::Decrypt    => self.show_decrypt(ui),
                Tab::License    => self.show_license(ui),
                Tab::Fingerprint => self.show_fingerprint(ui),
            }
        });
    }
}

impl Lab2App {
    fn show_encrypt(&mut self, ui: &mut Ui) {
        ui.heading("🔒 Шифрование файла (AES-256-CBC)");
        ui.separator();

        Grid::new("enc_grid").num_columns(2).spacing([8.0, 8.0]).show(ui, |ui| {
            ui.label("Путь к файлу:");
            ui.text_edit_singleline(&mut self.enc_path);
            ui.end_row();
            ui.label("Пароль шифрования:");
            ui.add(TextEdit::singleline(&mut self.enc_password).password(true).desired_width(220.0));
            ui.end_row();
        });

        ui.add_space(8.0);
        if ui.button("  Зашифровать  ").clicked() { self.do_encrypt(); }
        ui.add_space(8.0);
        if !self.enc_status.is_empty() {
            let color = if self.enc_status.starts_with("✅") { Color32::GREEN } else { Color32::RED };
            ui.colored_label(color, &self.enc_status.clone());
        }

        ui.add_space(16.0);
        ui.separator();
        ui.label("Формат зашифрованного файла: base64(IV[16] || AES-256-CBC(данные))");
        ui.label("Расширение: <исходное>.drm");
        ui.label("Лицензионный ключ сохраняется в папке licenses/");
    }

    fn show_decrypt(&mut self, ui: &mut Ui) {
        ui.heading("🔓 Защищённый просмотрщик файлов");
        ui.separator();

        Grid::new("dec_grid").num_columns(2).spacing([8.0, 8.0]).show(ui, |ui| {
            ui.label("Путь к .drm файлу:");
            ui.text_edit_singleline(&mut self.dec_path);
            ui.end_row();
            ui.label("Метод доступа:");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.dec_use_license, false, "По паролю");
                ui.selectable_value(&mut self.dec_use_license, true,  "По лицензии");
            });
            ui.end_row();
            if !self.dec_use_license {
                ui.label("Пароль:");
                ui.add(TextEdit::singleline(&mut self.dec_password).password(true).desired_width(220.0));
                ui.end_row();
            } else {
                ui.label("Лицензионный ключ:");
                ui.text_edit_singleline(&mut self.dec_key);
                ui.end_row();
            }
        });

        ui.add_space(8.0);
        if ui.button("  Открыть файл  ").clicked() { self.do_decrypt(); }
        ui.add_space(4.0);
        let color = if self.dec_status.starts_with("✅") { Color32::GREEN } else { Color32::RED };
        if !self.dec_status.is_empty() {
            ui.colored_label(color, &self.dec_status.clone());
        }

        if !self.dec_content.is_empty() {
            ui.add_space(8.0);
            ui.separator();
            ui.label("Содержимое файла:");
            ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                ui.add(TextEdit::multiline(&mut self.dec_content)
                    .desired_width(f32::INFINITY)
                    .font(TextStyle::Monospace));
            });
        }
    }

    fn show_license(&mut self, ui: &mut Ui) {
        ui.heading("🗝 Управление лицензиями");
        ui.separator();

        ui.label("Имя файла (например: document.txt.drm):");
        ui.text_edit_singleline(&mut self.lic_filename);
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            if ui.button("Сгенерировать ключ").clicked() {
                let name = self.lic_filename.trim().to_string();
                if name.is_empty() {
                    self.lic_status = "❌ Введите имя файла.".into();
                } else {
                    self.lic_generated_key = generate_key(&name);
                    let _ = save_license(&name, &self.lic_generated_key);
                    self.lic_status = format!("✅ Лицензия сохранена в licenses/{}.license", name);
                }
            }
        });

        if !self.lic_generated_key.is_empty() {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("Ключ:");
                ui.strong(&self.lic_generated_key.clone());
                if ui.small_button("📋").on_hover_text("Скопировать").clicked() {
                    ui.ctx().copy_text(self.lic_generated_key.clone());
                }
            });
        }

        if !self.lic_status.is_empty() {
            let c = if self.lic_status.starts_with("✅") { Color32::GREEN } else { Color32::RED };
            ui.colored_label(c, &self.lic_status.clone());
        }

        ui.add_space(16.0);
        ui.separator();
        ui.label("ℹ Лицензионный ключ привязан к аппаратному отпечатку данного компьютера.");
        ui.label("ℹ Ключ не будет действителен на другой машине.");
    }

    fn show_fingerprint(&mut self, ui: &mut Ui) {
        ui.heading("💻 Аппаратный отпечаток (Hardware Fingerprint)");
        ui.separator();
        ui.label("Параметры, использованные для привязки лицензии:");
        ui.add_space(8.0);

        Grid::new("fp_grid").num_columns(2).striped(true).spacing([12.0, 6.0]).show(ui, |ui| {
            for (k, v) in &self.fp_params {
                ui.strong(k);
                ui.label(v);
                ui.end_row();
            }
        });

        ui.add_space(12.0);
        ui.label(format!("SHA-256: {}", &self.fp_hash));
    }
}

