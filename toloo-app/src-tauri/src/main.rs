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

        // AppImage bundles its own Mesa/EGL libraries which can conflict with
        // the host system's GPU stack, causing:
        //   "Could not create default EGL display: EGL_BAD_PARAMETER. Aborting..."
        // Disabling accelerated compositing makes WebKit fall back to software
        // rendering, which works on all systems. Users can opt out by setting
        // WEBKIT_DISABLE_COMPOSITING_MODE=0 in their environment.
        if env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() {
            env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        }
    }

    toloo_app_lib::run()
}
