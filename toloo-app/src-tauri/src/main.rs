#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
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

        // WebKitGTK's DMABuf renderer fails on systems where EGL can't create a
        // display (NVIDIA proprietary drivers, VMs, certain Mesa configs), printing
        // "Could not create default EGL display: EGL_BAD_PARAMETER. Aborting..."
        // Disabling it makes WebKit fall back to software compositing, which works
        // everywhere. Only set when the user hasn't already provided an override.
        if env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }

    toloo_app_lib::run()
}
