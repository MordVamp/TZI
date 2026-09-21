mod model;
mod password;
mod signature;
mod storage;
mod app;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ПАСЗИ — Лабораторная работа №1")
            .with_inner_size([900.0, 620.0])
            .with_min_inner_size([700.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "lab1",
        options,
        Box::new(|cc| Ok(Box::new(app::Lab1App::new(cc)))),
    )
}
