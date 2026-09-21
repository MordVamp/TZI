use serde::{Deserialize, Serialize};

// ─── Подгруппа ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Subgroup {
    PG1,
    PG2,
}

impl std::fmt::Display for Subgroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Subgroup::PG1 => write!(f, "ПГ-1"),
            Subgroup::PG2 => write!(f, "ПГ-2"),
        }
    }
}

// ─── Пользователь ───────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String, // SHA-256 hex
    pub blocked: bool,
    pub restrictions_enabled: bool,
    /// ПГ-1: индивидуальная минимальная длина пароля
    pub min_password_len: usize,
    /// ПГ-1: аутентификация по сертификату на USB
    pub use_certificate: bool,
}

impl User {
    pub fn new_admin() -> Self {
        Self {
            username: "ADMIN".to_string(),
            password_hash: crate::storage::hash_password(""),
            blocked: false,
            restrictions_enabled: false,
            min_password_len: 6,
            use_certificate: false,
        }
    }

    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
            password_hash: crate::storage::hash_password(""),
            blocked: false,
            restrictions_enabled: false,
            min_password_len: 6,
            use_certificate: false,
        }
    }

    pub fn is_admin(&self) -> bool {
        self.username == "ADMIN"
    }
}

// ─── Настройки ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Текущая подгруппа (ПГ-1 / ПГ-2)
    pub subgroup: Subgroup,
    /// ПГ-1: путь/буква диска USB-носителей с сертификатами
    pub cert_drive: String,
    /// ПГ-2: глобальная минимальная длина пароля
    pub global_min_password_len: usize,
    /// ПГ-2: сохранённая сигнатура компьютера
    pub computer_signature: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            subgroup: Subgroup::PG1,
            cert_drive: "/media".to_string(),
            global_min_password_len: 8,
            computer_signature: None,
        }
    }
}

// ─── Хранилище пользователей ─────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserDb {
    pub users: Vec<User>,
}

impl UserDb {
    pub fn get(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut User> {
        self.users.iter_mut().find(|u| u.username == name)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.users.iter().any(|u| u.username == name)
    }

    pub fn add(&mut self, user: User) -> bool {
        if self.exists(&user.username) {
            return false;
        }
        self.users.push(user);
        true
    }

    /// Удалить пользователя по имени. Нельзя удалить ADMIN.
    pub fn remove(&mut self, name: &str) -> bool {
        if name == "ADMIN" {
            return false;
        }
        let before = self.users.len();
        self.users.retain(|u| u.username != name);
        self.users.len() < before
    }

    /// Переименовать пользователя. Нельзя переименовать ADMIN или дать имя уже существующему.
    pub fn rename(&mut self, old_name: &str, new_name: &str) -> Result<(), &'static str> {
        if old_name == "ADMIN" {
            return Err("Нельзя переименовать ADMIN.");
        }
        if new_name.trim().is_empty() {
            return Err("Имя не может быть пустым.");
        }
        if self.exists(new_name) {
            return Err("Пользователь с таким именем уже существует.");
        }
        match self.users.iter_mut().find(|u| u.username == old_name) {
            Some(u) => { u.username = new_name.to_string(); Ok(()) }
            None => Err("Пользователь не найден."),
        }
    }
}
