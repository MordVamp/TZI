/// Результат проверки одного требования
#[derive(Debug, Clone)]
pub struct Check {
    pub label: String,
    pub passed: bool,
}

impl Check {
    fn new(label: impl Into<String>, passed: bool) -> Self {
        Self { label: label.into(), passed }
    }
}

// ─── ПГ-1 ────────────────────────────────────────────────────────────────────
/// Проверка сложности пароля по требованиям ПГ-1.
///
/// 1. Длина ≥ min_len (индивидуальная для пользователя)
/// 2. Наличие строчных букв
/// 3. Наличие прописных букв
/// 4. Наличие цифр
/// 5. Наличие знаков препинания
/// 6. Отсутствие повторяющихся символов
pub fn check_pg1(password: &str, min_len: usize) -> Vec<Check> {
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_punct = password.chars().any(|c| {
        matches!(c, '!'|'"'|'#'|'$'|'%'|'&'|'\''|'('|')'|'*'|'+'|','|'-'|'.'|'/'|
                    ':'|';'|'<'|'='|'>'|'?'|'@'|'['|'\\'|']'|'^'|'_'|'`'|'{'|'|'|'}'|'~')
    });

    let mut seen = std::collections::HashSet::new();
    let no_repeats = password.chars().all(|c| seen.insert(c));

    vec![
        Check::new(format!("Длина ≥ {} символов (сейчас {})", min_len, password.len()),
                   password.len() >= min_len),
        Check::new("Строчные буквы", has_lower),
        Check::new("Прописные буквы", has_upper),
        Check::new("Цифры", has_digit),
        Check::new("Знаки препинания", has_punct),
        Check::new("Нет повторяющихся символов", no_repeats),
    ]
}

pub fn pg1_valid(password: &str, min_len: usize) -> bool {
    check_pg1(password, min_len).iter().all(|c| c.passed)
}

// ─── ПГ-2 ────────────────────────────────────────────────────────────────────
/// Проверка сложности пароля по требованиям ПГ-2.
///
/// 1. Длина ≥ global_min_len (глобальная для всех)
/// 2. Наличие латинских букв
/// 3. Наличие символов кириллицы
/// 4. Наличие знаков арифметических операций (+, -, *, /)
/// 5. Отсутствие подряд расположенных одинаковых символов
/// 6. Несовпадение с именем пользователя, записанным в обратном порядке
pub fn check_pg2(password: &str, username: &str, global_min_len: usize) -> Vec<Check> {
    let has_latin = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_cyrillic = password.chars().any(|c| {
        matches!(c as u32, 0x0410..=0x044F | 0x0451 | 0x0401)
    });
    let has_arith = password.chars().any(|c| matches!(c, '+' | '-' | '*' | '/'));

    let no_consecutive = password
        .chars()
        .collect::<Vec<_>>()
        .windows(2)
        .all(|w| w[0] != w[1]);

    let reversed_username: String = username.chars().rev().collect();
    let not_reversed = password != reversed_username.as_str();

    vec![
        Check::new(
            format!("Длина ≥ {} символов (сейчас {})", global_min_len, password.len()),
            password.len() >= global_min_len,
        ),
        Check::new("Латинские буквы", has_latin),
        Check::new("Символы кириллицы", has_cyrillic),
        Check::new("Знаки арифметических операций (+, -, *, /)", has_arith),
        Check::new("Нет подряд одинаковых символов", no_consecutive),
        Check::new("Не совпадает с именем пользователя в обратном порядке", not_reversed),
    ]
}

pub fn pg2_valid(password: &str, username: &str, global_min_len: usize) -> bool {
    check_pg2(password, username, global_min_len).iter().all(|c| c.passed)
}
