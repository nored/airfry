use std::path::{Path, PathBuf};
use std::process::Command;

fn qmake(query: &str) -> String {
    let out = Command::new("qmake6")
        .args(["-query", query])
        .output()
        .unwrap_or_else(|e| panic!("failed to run qmake6 -query {query}: {e}"));
    if !out.status.success() {
        panic!(
            "qmake6 -query {query} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn find_moc(libexecs: &str) -> PathBuf {
    let candidate = Path::new(libexecs).join("moc");
    if candidate.exists() {
        return candidate;
    }
    for p in ["/usr/lib/qt6/moc", "/usr/bin/moc"] {
        if Path::new(p).exists() {
            return PathBuf::from(p);
        }
    }
    panic!("could not locate the Qt6 `moc` (looked in {libexecs}, /usr/lib/qt6, /usr/bin)");
}

fn main() {
    println!("cargo:rerun-if-changed=cpp/tray.cpp");
    println!("cargo:rerun-if-changed=cpp/tray.h");
    println!("cargo:rerun-if-changed=build.rs");

    let qt_headers = qmake("QT_INSTALL_HEADERS");
    let qt_libs = qmake("QT_INSTALL_LIBS");
    let qt_libexecs = qmake("QT_INSTALL_LIBEXECS");
    let moc = find_moc(&qt_libexecs);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // ---- Run moc on tray.cpp (it carries Q_OBJECT + includes "tray.moc"). ----
    // tray.cpp #include "tray.moc" at the bottom, so we moc the .cpp itself and
    // place the output where the compiler can find it via an include path.
    let moc_out = out_dir.join("tray.moc");
    let status = Command::new(&moc)
        .arg("cpp/tray.cpp")
        .arg("-I")
        .arg(&qt_headers)
        .arg("-o")
        .arg(&moc_out)
        .status()
        .expect("failed to spawn moc");
    assert!(status.success(), "moc failed on cpp/tray.cpp");

    // ---- Compile tray.cpp; OUT_DIR include lets it find tray.moc. ----
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .flag("-fPIC")
        .file("cpp/tray.cpp")
        .include("cpp")
        .include(&out_dir)
        .include(&qt_headers)
        .include(format!("{qt_headers}/QtCore"))
        .include(format!("{qt_headers}/QtGui"))
        .include(format!("{qt_headers}/QtWidgets"))
        // Qt headers require these.
        .flag_if_supported("-Wno-deprecated-declarations");

    build.compile("airfry_tray");

    // ---- Link Qt6. ----
    println!("cargo:rustc-link-search=native={qt_libs}");
    println!("cargo:rustc-link-lib=Qt6Widgets");
    println!("cargo:rustc-link-lib=Qt6Gui");
    println!("cargo:rustc-link-lib=Qt6Core");
    // The C++ standard library is needed since we compiled C++ TUs.
    println!("cargo:rustc-link-lib=stdc++");
}
