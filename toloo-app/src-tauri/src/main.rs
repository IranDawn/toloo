#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // On Linux, pick the right GTK backend before GTK initialises.
    // Without this, pure-Wayland sessions (no DISPLAY) fail with
    // "Failed to initialize GTK" because GTK defaults to the X11 backend.
    #[cfg(target_os = "linux")]
    {
        use std::env;
        let has_wayland = env::var_os("WAYLAND_DISPLAY").is_some();
        let has_x11     = env::var_os("DISPLAY").is_some();
        // The AppImage's AppRun hook unconditionally sets GDK_BACKEND=x11.
        // Override it here based on what display servers are actually available,
        // so pure-Wayland sessions (no DISPLAY) don't fail to initialise GTK.
        if has_wayland && !has_x11 {
            env::set_var("GDK_BACKEND", "wayland");
        }
    }

    toloo_app_lib::run()
}
