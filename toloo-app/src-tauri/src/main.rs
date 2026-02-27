#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "linux")]
    {
        use std::env;
        let has_wayland = env::var_os("WAYLAND_DISPLAY").is_some();
        let has_x11     = env::var_os("DISPLAY").is_some();
        // Prefer Wayland when X11 is not available (pure-Wayland sessions).
        if has_wayland && !has_x11 {
            env::set_var("GDK_BACKEND", "wayland");
        }
    }

    toloo_app_lib::run()
}
