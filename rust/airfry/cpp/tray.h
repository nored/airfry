#ifndef AIRFRY_TRAY_H
#define AIRFRY_TRAY_H

#ifdef __cplusplus
extern "C" {
#endif

/* Callbacks invoked by the C++ tray, dispatched back into Rust.
 * `ctx` is an opaque pointer the Rust side may use (we use globals, so it can
 * be null). All callbacks are invoked on the GUI (main) thread. */
typedef struct {
    void* ctx;
    void (*on_ready)(void*);                       /* tray shown, event loop live */
    void (*on_rescan)(void*);                       /* menu about to show / Rescan */
    void (*on_device)(void*, const char* addr);     /* a device entry triggered */
    void (*on_underscan)(void*, int pct);           /* slider value changed */
    void (*on_quit)(void*);                         /* Quit selected */
} AirfryTrayCallbacks;

/* Build QApplication + tray + menu, run app.exec(). BLOCKS the calling
 * (main) thread until the app quits. Returns the exec() exit code.
 * `initial_pct` seeds the underscan slider. */
int airfry_tray_run(const AirfryTrayCallbacks* cb, int initial_pct);

/* Replace the device list. Thread-safe: marshals onto the GUI thread.
 * `names` and `addrs` are parallel arrays of length `n` (UTF-8, addr is
 * "ip:port"). */
void airfry_tray_set_devices(const char* const* names,
                             const char* const* addrs, int n);

/* Set the status/section header line. Thread-safe (marshals onto GUI thread). */
void airfry_tray_set_status(const char* text);

#ifdef __cplusplus
}
#endif

#endif /* AIRFRY_TRAY_H */
