use egui::*;
use crate::{model::*, password::*, signature::*, storage::*};

#[derive(PartialEq)]
enum Screen { Login, Admin, User }

pub struct Lab1App {
    screen: Screen,
    db: UserDb,
    settings: Settings,
    current_user: String,
    // login
    l_user: String, l_pass: String, l_err: String, l_attempts: u32,
    // dialogs
    dlg_add: bool, dlg_about: bool, dlg_settings: bool,
    dlg_adm_cp: bool, dlg_usr_cp: bool, dlg_sig: bool,
    dlg_del_user: bool, del_target: String,
    // rename user
    dlg_rename: bool, rename_target: String, rename_new: String, rename_err: String,
    // admin force change user password
    dlg_force_cp: bool, force_target: String,
    force_new: String, force_con: String, force_err: String,
    force_checks: Vec<Check>,
    // add user
    new_name: String, new_err: String,
    // admin change password
    acp_old: String, acp_new: String, acp_con: String, acp_err: String,
    acp_checks: Vec<Check>,
    // user change password
    ucp_old: String, ucp_new: String, ucp_con: String, ucp_err: String,
    ucp_checks: Vec<Check>, ucp_ok: bool,
    // settings edit
    se_drive: String, se_minlen: String,
    // status bar
    status: String,
    // PG-2 signature
    sig_current: String, sig_warning: String,
    sig_params: Vec<(String, String)>,
}

impl Lab1App {
    pub fn new(_cc: &eframe::CreationContext) -> Self {
        let db = load_users();
        let settings = load_settings();
        let sig = compute_signature();
        let sig_warning = if settings.subgroup == Subgroup::PG2 {
            match &settings.computer_signature {
                Some(stored) if stored != &sig =>
                    "⚠ Обнаружено несанкционированное копирование! Сигнатура не совпадает.".into(),
                _ => String::new(),
            }
        } else { String::new() };
        Self {
            screen: Screen::Login,
            db, settings,
            current_user: String::new(),
            l_user: String::new(), l_pass: String::new(),
            l_err: String::new(), l_attempts: 0,
            dlg_add: false, dlg_about: false, dlg_settings: false,
            dlg_adm_cp: false, dlg_usr_cp: false, dlg_sig: false,
            dlg_del_user: false, del_target: String::new(),
            dlg_rename: false, rename_target: String::new(),
            rename_new: String::new(), rename_err: String::new(),
            dlg_force_cp: false, force_target: String::new(),
            force_new: String::new(), force_con: String::new(),
            force_err: String::new(), force_checks: vec![],
            new_name: String::new(), new_err: String::new(),
            acp_old: String::new(), acp_new: String::new(),
            acp_con: String::new(), acp_err: String::new(), acp_checks: vec![],
            ucp_old: String::new(), ucp_new: String::new(),
            ucp_con: String::new(), ucp_err: String::new(),
            ucp_checks: vec![], ucp_ok: false,
            se_drive: String::new(), se_minlen: String::new(),
            status: "Готово".into(),
            sig_current: sig,
            sig_warning,
            sig_params: signature_params(),
        }
    }

    fn do_login(&mut self, ctx: &Context) {
        let name = self.l_user.trim().to_string();
        let pass = self.l_pass.clone();
        let user = match self.db.get(&name) {
            Some(u) => u.clone(),
            None => { self.l_err = "Пользователь не найден.".into(); return; }
        };
        if user.blocked { self.l_err = "Учётная запись заблокирована.".into(); return; }
        if !verify_password(&user, &pass) {
            self.l_attempts += 1;
            if self.l_attempts >= 3 {
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
            self.l_err = format!("Неверный пароль. Попытка {}/3.", self.l_attempts);
            self.l_pass.clear();
            return;
        }
        self.current_user = name.clone();
        self.l_err.clear(); self.l_pass.clear();
        self.screen = if user.is_admin() { Screen::Admin } else { Screen::User };
        self.status = format!("Вход выполнен: {}", name);
    }

    fn logout(&mut self) {
        self.screen = Screen::Login;
        self.l_user.clear(); self.l_pass.clear(); self.l_err.clear();
        self.l_attempts = 0; self.current_user.clear();
    }

    fn password_checks(&self, pass: &str, user: &str) -> Vec<Check> {
        match self.settings.subgroup {
            Subgroup::PG1 => {
                let min = self.db.get(user)
                    .map(|u| u.min_password_len)
                    .unwrap_or(6);
                check_pg1(pass, min)
            }
            Subgroup::PG2 => check_pg2(pass, user, self.settings.global_min_password_len),
        }
    }
}

impl eframe::App for Lab1App {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // Dark theme
        ctx.set_visuals(Visuals::dark());

        match self.screen {
            Screen::Login => self.show_login(ctx),
            Screen::Admin => self.show_admin(ctx),
            Screen::User  => self.show_user(ctx),
        }

        self.show_about_dlg(ctx);
        self.show_add_user_dlg(ctx);
        self.show_settings_dlg(ctx);
        self.show_adm_cp_dlg(ctx);
        self.show_usr_cp_dlg(ctx);
        self.show_sig_dlg(ctx);
        self.show_delete_user_dlg(ctx);
        self.show_rename_user_dlg(ctx);
        self.show_force_cp_dlg(ctx);
    }
}

// ─── Экран входа ─────────────────────────────────────────────────────────────
impl Lab1App {
    fn show_login(&mut self, ctx: &Context) {
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(80.0);
                ui.heading("🔐  Система разграничения доступа");
                ui.label("Лабораторная работа №1 — ПАСЗИ");
                ui.add_space(30.0);

                let w = 300.0;
                ui.allocate_ui(vec2(w, 200.0), |ui| {
                    Grid::new("login_grid").num_columns(2).spacing([8.0, 10.0]).show(ui, |ui| {
                        ui.label("Имя пользователя:");
                        ui.add(TextEdit::singleline(&mut self.l_user).desired_width(180.0));
                        ui.end_row();
                        ui.label("Пароль:");
                        ui.add(TextEdit::singleline(&mut self.l_pass)
                            .desired_width(180.0).password(true));
                        ui.end_row();
                    });

                    ui.add_space(12.0);
                    if !self.l_err.is_empty() {
                        ui.colored_label(Color32::from_rgb(255, 100, 100), &self.l_err.clone());
                        ui.add_space(6.0);
                    }

                    ui.horizontal(|ui| {
                        let enter = ui.input(|i| i.key_pressed(Key::Enter));
                        if ui.button("  Войти  ").clicked() || enter {
                            let ctx2 = ctx.clone();
                            self.do_login(&ctx2);
                        }
                        if ui.button("Выход").clicked() {
                            ctx.send_viewport_cmd(ViewportCommand::Close);
                        }
                    });
                });

                if self.l_attempts > 0 {
                    ui.add_space(8.0);
                    ui.colored_label(Color32::YELLOW,
                        format!("Осталось попыток: {}", 3 - self.l_attempts));
                }
            });
        });
    }
}

// ─── Панель администратора ────────────────────────────────────────────────────
impl Lab1App {
    fn show_admin(&mut self, ctx: &Context) {
        if !self.sig_warning.is_empty() {
            TopBottomPanel::top("sig_warn").show(ctx, |ui| {
                ui.colored_label(Color32::from_rgb(255, 180, 0), &self.sig_warning.clone());
            });
        }

        TopBottomPanel::top("menu").show(ctx, |ui| {
            menu::bar(ui, |ui| {
                ui.menu_button("Пользователи", |ui| {
                    if ui.button("Добавить пользователя").clicked() {
                        self.new_name.clear(); self.new_err.clear();
                        self.dlg_add = true; ui.close_menu();
                    }
                    if ui.button("Сменить пароль администратора").clicked() {
                        self.acp_old.clear(); self.acp_new.clear();
                        self.acp_con.clear(); self.acp_err.clear(); self.acp_checks.clear();
                        self.dlg_adm_cp = true; ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Выйти из системы").clicked() { self.logout(); ui.close_menu(); }
                });
                ui.menu_button("Безопасность", |ui| {
                    if ui.button("Настройки").clicked() {
                        self.se_drive = self.settings.cert_drive.clone();
                        self.se_minlen = self.settings.global_min_password_len.to_string();
                        self.dlg_settings = true; ui.close_menu();
                    }
                    if self.settings.subgroup == Subgroup::PG2 {
                        if ui.button("Сигнатура компьютера").clicked() {
                            self.dlg_sig = true; ui.close_menu();
                        }
                    }
                });
                ui.menu_button("Справка", |ui| {
                    if ui.button("О программе").clicked() {
                        self.dlg_about = true; ui.close_menu();
                    }
                });
            });
        });

        TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("👤 {}", self.current_user));
                ui.separator();
                ui.label(format!("Режим: {}", self.settings.subgroup));
                ui.separator();
                ui.label(&self.status.clone());
            });
        });

        CentralPanel::default().show(ctx, |ui| {
            ui.heading("Список пользователей");
            ui.separator();

            let users: Vec<User> = self.db.users.clone();
            ScrollArea::vertical().show(ui, |ui| {
                Grid::new("users_grid")
                    .num_columns(6)
                    .striped(true)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.strong("Имя"); ui.strong("Заблокирован");
                        ui.strong("Ограничения"); ui.strong("Мин. пароль");
                        ui.strong("Сертификат"); ui.strong("Действия");
                        ui.end_row();

                        for u in &users {
                            let name = u.username.clone();
                            ui.label(&name);
                            ui.label(if u.blocked { "🔒 Да" } else { "✅ Нет" });
                            ui.label(if u.restrictions_enabled { "Вкл" } else { "Выкл" });
                            ui.label(u.min_password_len.to_string());
                            ui.label(if u.use_certificate { "Да" } else { "Нет" });

                            ui.horizontal(|ui| {
                                if !u.is_admin() {
                                    let lbl = if u.blocked { "Разблокировать" } else { "Заблокировать" };
                                    if ui.small_button(lbl).clicked() {
                                        if let Some(usr) = self.db.get_mut(&name) {
                                            usr.blocked = !usr.blocked;
                                        }
                                        save_users(&self.db);
                                        self.status = format!("Пользователь {} обновлён.", name);
                                    }
                                    // toggle restrictions
                                    if ui.small_button("±Огр.").clicked() {
                                        if let Some(usr) = self.db.get_mut(&name) {
                                            usr.restrictions_enabled = !usr.restrictions_enabled;
                                        }
                                        save_users(&self.db);
                                    }
                                    // min len
                                    if let Some(usr) = self.db.get_mut(&name) {
                                        let mut ml = usr.min_password_len;
                                        if ui.add(egui::DragValue::new(&mut ml).range(1..=32usize)).changed() {
                                            usr.min_password_len = ml;
                                            save_users(&self.db);
                                        }
                                    }
                                    // rename
                                    if ui.small_button("✏ Имя").clicked() {
                                        self.rename_target = name.clone();
                                        self.rename_new = name.clone();
                                        self.rename_err.clear();
                                        self.dlg_rename = true;
                                    }
                                    // force change password
                                    if ui.small_button("🔑 Пароль").clicked() {
                                        self.force_target = name.clone();
                                        self.force_new.clear();
                                        self.force_con.clear();
                                        self.force_err.clear();
                                        self.force_checks.clear();
                                        self.dlg_force_cp = true;
                                    }
                                    // delete
                                    if ui.small_button("🗑 Удалить").clicked() {
                                        self.del_target = name.clone();
                                        self.dlg_del_user = true;
                                    }
                                }
                            });
                            ui.end_row();
                        }
                    });
            });
        });
    }
}

// ─── Панель пользователя ──────────────────────────────────────────────────────
impl Lab1App {
    fn show_user(&mut self, ctx: &Context) {
        TopBottomPanel::top("umenu").show(ctx, |ui| {
            menu::bar(ui, |ui| {
                ui.menu_button("Пользователь", |ui| {
                    if ui.button("Сменить пароль").clicked() {
                        self.ucp_old.clear(); self.ucp_new.clear();
                        self.ucp_con.clear(); self.ucp_err.clear();
                        self.ucp_checks.clear(); self.ucp_ok = false;
                        self.dlg_usr_cp = true; ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Выход").clicked() { self.logout(); ui.close_menu(); }
                });
                ui.menu_button("Справка", |ui| {
                    if ui.button("О программе").clicked() {
                        self.dlg_about = true; ui.close_menu();
                    }
                });
            });
        });

        TopBottomPanel::bottom("ustatus").show(ctx, |ui| {
            ui.label(format!("👤 {} | Режим: {}", self.current_user, self.settings.subgroup));
        });

        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading(format!("Добро пожаловать, {}!", self.current_user));
                ui.add_space(12.0);
                ui.label("Доступные действия: смена пароля.");
                ui.add_space(20.0);
                if ui.button("  Сменить пароль  ").clicked() {
                    self.ucp_old.clear(); self.ucp_new.clear();
                    self.ucp_con.clear(); self.ucp_err.clear();
                    self.ucp_checks.clear(); self.ucp_ok = false;
                    self.dlg_usr_cp = true;
                }
            });
        });
    }
}

// ─── Диалоги ──────────────────────────────────────────────────────────────────
impl Lab1App {
    fn show_about_dlg(&mut self, ctx: &Context) {
        if !self.dlg_about { return; }
        Window::new("О программе").open(&mut self.dlg_about).resizable(false).show(ctx, |ui| {
            ui.label("Лабораторная работа №1");
            ui.label("Тема: Разработка ПО разграничения полномочий пользователей");
            ui.separator();
            ui.label("Реализованы подгруппы ПГ-1 и ПГ-2.");
            ui.label("ПГ-1: проверка сложности пароля, USB-сертификат.");
            ui.label("ПГ-2: сигнатура компьютера, кириллица/латиница.");
        });
    }

    fn show_add_user_dlg(&mut self, ctx: &Context) {
        if !self.dlg_add { return; }
        let mut open = self.dlg_add;
        Window::new("Добавить пользователя").open(&mut open).resizable(false).show(ctx, |ui| {
            ui.label("Новое имя пользователя:");
            ui.text_edit_singleline(&mut self.new_name);
            if !self.new_err.is_empty() {
                ui.colored_label(Color32::from_rgb(255, 100, 100), &self.new_err.clone());
            }
            ui.horizontal(|ui| {
                if ui.button("Добавить").clicked() {
                    let name = self.new_name.trim().to_string();
                    if name.is_empty() {
                        self.new_err = "Имя не может быть пустым.".into();
                    } else if !self.db.add(User::new(&name)) {
                        self.new_err = "Пользователь уже существует.".into();
                    } else {
                        save_users(&self.db);
                        self.status = format!("Пользователь {} добавлен.", name);
                        self.new_name.clear(); self.new_err.clear();
                        self.dlg_add = false;
                    }
                }
                if ui.button("Отмена").clicked() { self.dlg_add = false; }
            });
        });
        self.dlg_add = open;
    }

    fn show_settings_dlg(&mut self, ctx: &Context) {
        if !self.dlg_settings { return; }
        let mut open = self.dlg_settings;
        Window::new("Настройки").open(&mut open).resizable(false).show(ctx, |ui| {
            ui.label("Подгруппа:");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.settings.subgroup, Subgroup::PG1, "ПГ-1");
                ui.selectable_value(&mut self.settings.subgroup, Subgroup::PG2, "ПГ-2");
            });
            ui.separator();
            ui.label("ПГ-1: Путь к USB-носителям с сертификатами:");
            ui.text_edit_singleline(&mut self.se_drive);
            ui.separator();
            ui.label("ПГ-2: Глобальная мин. длина пароля:");
            ui.text_edit_singleline(&mut self.se_minlen);
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Сохранить").clicked() {
                    self.settings.cert_drive = self.se_drive.trim().to_string();
                    if let Ok(v) = self.se_minlen.trim().parse::<usize>() {
                        self.settings.global_min_password_len = v;
                    }
                    if self.settings.subgroup == Subgroup::PG2
                        && self.settings.computer_signature.is_none()
                    {
                        self.settings.computer_signature = Some(self.sig_current.clone());
                    }
                    save_settings(&self.settings);
                    self.status = "Настройки сохранены.".into();
                    self.dlg_settings = false;
                }
                if ui.button("Отмена").clicked() { self.dlg_settings = false; }
            });
        });
        self.dlg_settings = open;
    }

    fn show_adm_cp_dlg(&mut self, ctx: &Context) {
        if !self.dlg_adm_cp { return; }
        let user = self.current_user.clone();
        let mut open = self.dlg_adm_cp;
        Window::new("Смена пароля (администратор)").open(&mut open).resizable(false).show(ctx, |ui| {
            Grid::new("acp").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label("Старый пароль:");
                ui.add(TextEdit::singleline(&mut self.acp_old).password(true).desired_width(180.0));
                ui.end_row();
                ui.label("Новый пароль:");
                let changed = ui.add(TextEdit::singleline(&mut self.acp_new)
                    .password(true).desired_width(180.0)).changed();
                ui.end_row();
                ui.label("Подтверждение:");
                ui.add(TextEdit::singleline(&mut self.acp_con).password(true).desired_width(180.0));
                ui.end_row();
                if changed {
                    self.acp_checks = self.password_checks(&self.acp_new.clone(), &user);
                }
            });

            if !self.acp_checks.is_empty() {
                ui.separator();
                ui.label("Требования к паролю:");
                for c in &self.acp_checks {
                    let icon = if c.passed { "✅" } else { "❌" };
                    ui.label(format!("{} {}", icon, c.label));
                }
            }

            if !self.acp_err.is_empty() {
                ui.colored_label(Color32::from_rgb(255, 100, 100), &self.acp_err.clone());
            }

            ui.horizontal(|ui| {
                if ui.button("Сохранить").clicked() {
                    let adm = self.db.get("ADMIN").cloned().unwrap();
                    if !verify_password(&adm, &self.acp_old) {
                        self.acp_err = "Неверный старый пароль.".into();
                    } else if self.acp_new != self.acp_con {
                        self.acp_err = "Пароли не совпадают.".into();
                    } else if adm.restrictions_enabled
                        && !self.acp_checks.iter().all(|c| c.passed)
                    {
                        self.acp_err = "Пароль не соответствует требованиям.".into();
                    } else {
                        if let Some(u) = self.db.get_mut("ADMIN") {
                            u.password_hash = crate::storage::hash_password(&self.acp_new);
                        }
                        save_users(&self.db);
                        self.status = "Пароль администратора изменён.".into();
                        self.dlg_adm_cp = false;
                    }
                }
                if ui.button("Отмена").clicked() { self.dlg_adm_cp = false; }
            });
        });
        self.dlg_adm_cp = open;
    }

    fn show_usr_cp_dlg(&mut self, ctx: &Context) {
        if !self.dlg_usr_cp { return; }
        let user = self.current_user.clone();
        let mut open = self.dlg_usr_cp;
        Window::new("Смена пароля").open(&mut open).resizable(false).show(ctx, |ui| {
            if self.ucp_ok {
                ui.colored_label(Color32::GREEN, "✅ Пароль успешно изменён!");
                if ui.button("Закрыть").clicked() { self.dlg_usr_cp = false; }
            } else {
                Grid::new("ucp").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                    ui.label("Старый пароль:");
                    ui.add(TextEdit::singleline(&mut self.ucp_old).password(true).desired_width(180.0));
                    ui.end_row();
                    ui.label("Новый пароль:");
                    let changed = ui.add(TextEdit::singleline(&mut self.ucp_new)
                        .password(true).desired_width(180.0)).changed();
                    ui.end_row();
                    ui.label("Подтверждение:");
                    ui.add(TextEdit::singleline(&mut self.ucp_con).password(true).desired_width(180.0));
                    ui.end_row();
                    if changed {
                        self.ucp_checks = self.password_checks(&self.ucp_new.clone(), &user);
                    }
                });

                if !self.ucp_checks.is_empty() {
                    ui.separator();
                    for c in &self.ucp_checks {
                        ui.label(format!("{} {}", if c.passed { "✅" } else { "❌" }, c.label));
                    }
                }

                if !self.ucp_err.is_empty() {
                    ui.colored_label(Color32::from_rgb(255, 100, 100), &self.ucp_err.clone());
                }

                ui.horizontal(|ui| {
                    if ui.button("Сохранить").clicked() {
                        let usr = self.db.get(&user).cloned().unwrap();
                        if !verify_password(&usr, &self.ucp_old) {
                            self.ucp_err = "Неверный старый пароль.".into();
                        } else if self.ucp_new != self.ucp_con {
                            self.ucp_err = "Пароли не совпадают.".into();
                        } else if usr.restrictions_enabled
                            && !self.ucp_checks.iter().all(|c| c.passed)
                        {
                            self.ucp_err = "Пароль не соответствует требованиям.".into();
                        } else {
                            if let Some(u) = self.db.get_mut(&user) {
                                u.password_hash = crate::storage::hash_password(&self.ucp_new);
                            }
                            save_users(&self.db);
                            self.status = "Пароль изменён.".into();
                            self.ucp_ok = true;
                        }
                    }
                    if ui.button("Отмена").clicked() { self.dlg_usr_cp = false; }
                });
            }
        });
        self.dlg_usr_cp = open;
    }

    fn show_rename_user_dlg(&mut self, ctx: &Context) {
        if !self.dlg_rename { return; }
        let target = self.rename_target.clone();
        let mut open = self.dlg_rename;
        Window::new("Переименовать пользователя")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!("Текущее имя: {}", target));
                ui.add_space(4.0);
                ui.label("Новое имя:");
                ui.text_edit_singleline(&mut self.rename_new);
                if !self.rename_err.is_empty() {
                    ui.colored_label(Color32::from_rgb(255, 100, 100), &self.rename_err.clone());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Сохранить").clicked() {
                        let new_name = self.rename_new.trim().to_string();
                        match self.db.rename(&target, &new_name) {
                            Ok(()) => {
                                save_users(&self.db);
                                self.status = format!("Пользователь {} переименован в {}.", target, new_name);
                                self.dlg_rename = false;
                            }
                            Err(e) => { self.rename_err = e.to_string(); }
                        }
                    }
                    if ui.button("Отмена").clicked() { self.dlg_rename = false; }
                });
            });
        self.dlg_rename = open;
    }

    fn show_force_cp_dlg(&mut self, ctx: &Context) {
        if !self.dlg_force_cp { return; }
        let target = self.force_target.clone();
        let mut open = self.dlg_force_cp;
        Window::new(format!("Сменить пароль: {}", target))
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                Grid::new("force_cp_grid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                    ui.label("Новый пароль:");
                    let changed = ui.add(
                        TextEdit::singleline(&mut self.force_new)
                            .password(true)
                            .desired_width(180.0)
                    ).changed();
                    ui.end_row();
                    ui.label("Подтверждение:");
                    ui.add(
                        TextEdit::singleline(&mut self.force_con)
                            .password(true)
                            .desired_width(180.0)
                    );
                    ui.end_row();
                    if changed {
                        self.force_checks = self.password_checks(&self.force_new.clone(), &target);
                    }
                });

                if !self.force_checks.is_empty() {
                    ui.separator();
                    ui.label("Требования к паролю:");
                    for c in &self.force_checks {
                        ui.label(format!("{} {}", if c.passed { "✅" } else { "❌" }, c.label));
                    }
                }

                if !self.force_err.is_empty() {
                    ui.colored_label(Color32::from_rgb(255, 100, 100), &self.force_err.clone());
                }

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.button("Сохранить").clicked() {
                        if self.force_new != self.force_con {
                            self.force_err = "Пароли не совпадают.".into();
                        } else {
                            let restrictions = self.db.get(&target)
                                .map(|u| u.restrictions_enabled)
                                .unwrap_or(false);
                            if restrictions && !self.force_checks.iter().all(|c| c.passed) {
                                self.force_err = "Пароль не соответствует требованиям.".into();
                            } else {
                                if let Some(u) = self.db.get_mut(&target) {
                                    u.password_hash = crate::storage::hash_password(&self.force_new);
                                }
                                save_users(&self.db);
                                self.status = format!("Пароль пользователя {} изменён.", target);
                                self.dlg_force_cp = false;
                            }
                        }
                    }
                    if ui.button("Отмена").clicked() { self.dlg_force_cp = false; }
                });
            });
        self.dlg_force_cp = open;
    }

    fn show_delete_user_dlg(&mut self, ctx: &Context) {
        if !self.dlg_del_user { return; }
        let target = self.del_target.clone();
        let mut open = self.dlg_del_user;
        Window::new("Подтверждение удаления")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.colored_label(
                    Color32::from_rgb(255, 100, 100),
                    format!("Удалить пользователя «{}»?", target),
                );
                ui.label("Это действие необратимо.");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("✅ Да, удалить").clicked() {
                        if self.db.remove(&target) {
                            save_users(&self.db);
                            self.status = format!("Пользователь {} удалён.", target);
                        }
                        self.dlg_del_user = false;
                    }
                    if ui.button("Отмена").clicked() {
                        self.dlg_del_user = false;
                    }
                });
            });
        self.dlg_del_user = open;
    }

    fn show_sig_dlg(&mut self, ctx: &Context) {
        if !self.dlg_sig { return; }
        let mut open = self.dlg_sig;
        Window::new("Сигнатура компьютера (ПГ-2)").open(&mut open).show(ctx, |ui| {
            ui.label("Параметры текущей системы:");
            Grid::new("sig_grid").num_columns(2).striped(true).show(ui, |ui| {
                for (k, v) in &self.sig_params {
                    ui.strong(k);
                    ui.label(v);
                    ui.end_row();
                }
            });
            ui.separator();
            ui.label(format!("Хэш: {}", &self.sig_current[..16]));
            match &self.settings.computer_signature {
                Some(s) => {
                    let ok = s == &self.sig_current;
                    let lbl = if ok { "✅ Совпадает с сохранённой" } else { "❌ Не совпадает!" };
                    ui.label(lbl);
                }
                None => { ui.label("Сигнатура не сохранена."); }
            }
            if ui.button("Записать текущую сигнатуру").clicked() {
                self.settings.computer_signature = Some(self.sig_current.clone());
                save_settings(&self.settings);
                self.sig_warning.clear();
                self.status = "Сигнатура компьютера сохранена.".into();
            }
        });
        self.dlg_sig = open;
    }
}
