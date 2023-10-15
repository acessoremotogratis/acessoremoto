use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_rdp_service_open(&self) -> bool {
        is_rdp_service_open()
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(id)
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_rdp_service_open();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
