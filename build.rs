fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    // 1. Configure & build the vendored RandomX library with cmake.
    let mut config = cmake::Config::new("./vendor/randomx");

    // Multi-config vs single-config generator compatibility:
    //
    //   * For multi-config generators (e.g. Visual Studio, Xcode), `.profile("Release")`
    //     ensures `cmake --build --config Release` is invoked. Without this, `--config`
    //     defaults to the Rust profile (Debug for `cargo test`/`cargo build`), which
    //     silently overrides `CMAKE_BUILD_TYPE=Release`.
    //   * For single-config generators (e.g. Ninja, Unix Makefiles), `CMAKE_BUILD_TYPE=Release`
    //     sets the optimization level and NDEBUG preprocessor definition.
    config.profile("Release");
    config.define("CMAKE_BUILD_TYPE", "Release");

    // Compiler-specific release flags:
    //
    //   * On MSVC (`target_env == "msvc"`): Rust's `x86_64-pc-windows-msvc` target always
    //     links against the release dynamic CRT (`/defaultlib:msvcrt`). An explicit `/MD`
    //     in `CMAKE_CXX_FLAGS_RELEASE` ensures the compiled objects link against `msvcrt.lib`,
    //     preventing unresolved `__imp__CrtDbgReport` linker errors.
    //   * On GCC / Clang (`target_env != "msvc"`): MSVC-style `/O2 /Ob2 /DNDEBUG /MD` flags
    //     are rejected as invalid compiler options. We emit standard POSIX compiler flags
    //     `-O3 -DNDEBUG` instead.
    if target_env == "msvc" {
        config.define("CMAKE_CXX_FLAGS_RELEASE", "/O2 /Ob2 /DNDEBUG /MD");
        config.define("CMAKE_C_FLAGS_RELEASE", "/O2 /Ob2 /DNDEBUG /MD");
    } else {
        config.define("CMAKE_CXX_FLAGS_RELEASE", "-O3 -DNDEBUG");
        config.define("CMAKE_C_FLAGS_RELEASE", "-O3 -DNDEBUG");
    }

    // Portable build: no CPU-specific native compilation, so the same
    // artefact is valid on every x86-64 host.
    config.define("ARCH", "default");

    let dst = config.build(); // builds the default "install" target

    // Register the static library so cargo links against it.
    println!("cargo:rustc-link-lib=static=randomx");
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );

    // Platform-specific linker dependencies:
    //
    //   * Windows: The RandomX static C++ library exports symbols that resolve against
    //     `advapi32.lib` at link time (Win32 virtual memory and security APIs).
    //   * Linux / macOS: Advapi32 does not exist; POSIX `mmap` / `sysconf` are used from
    //     the standard C library (libc), so advapi32 must not be linked.
    if target_os == "windows" {
        println!("cargo:rustc-link-lib=advapi32");
    }

    // 2. Re-run build script when the source or CMake config changes.
    println!("cargo:rerun-if-changed=vendor/randomx/src/randomx.h");
    println!("cargo:rerun-if-changed=vendor/randomx/src/configuration.h");
    println!("cargo:rerun-if-changed=vendor/randomx/CMakeLists.txt");
}
