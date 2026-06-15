// AirFry system-tray widget — a self-drawn Qt QMenu with an inline underscan
// QSlider (QWidgetAction). DBusMenu (the Wayland/GNOME StatusNotifierItem menu
// protocol) has no slider item type, so we force Qt to render the menu itself
// rather than export it over DBus. Only then can a real QSlider live in the
// tray menu.

#include "tray.h"

#include <QApplication>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QWidget>
#include <QWidgetAction>
#include <QHBoxLayout>
#include <QLabel>
#include <QSlider>
#include <QAction>
#include <QIcon>
#include <QPixmap>
#include <QPainter>
#include <QString>
#include <QVector>
#include <QMetaObject>
#include <Qt>

#include <vector>
#include <string>

// ---------------------------------------------------------------------------
// Controller QObject — owns the menu and reacts to Qt signals, forwarding into
// the Rust callbacks. Needs Q_OBJECT so moc generates the meta-object used by
// QMetaObject::invokeMethod() for cross-thread marshalling.
// ---------------------------------------------------------------------------
class TrayController : public QObject {
    Q_OBJECT
public:
    TrayController(const AirfryTrayCallbacks* cb, int initialPct, QObject* parent = nullptr)
        : QObject(parent), m_cb(*cb), m_initialPct(initialPct) {}

    void build();

    // Invokable so they can be called via QMetaObject::invokeMethod with a
    // QueuedConnection from worker threads.
    Q_INVOKABLE void applyDevices(QVector<QString> names, QVector<QString> addrs);
    Q_INVOKABLE void applyStatus(QString text);

private slots:
    void onAboutToShow();
    void onSliderChanged(int v);
    void onRescan();
    void onQuit();

public:
    QSystemTrayIcon* m_tray = nullptr;
    QMenu* m_menu = nullptr;

private:
    AirfryTrayCallbacks m_cb;
    int m_initialPct = 0;

    QAction* m_header = nullptr;   // "AirFry"
    QAction* m_status = nullptr;   // "Scanning…" / device count
    QAction* m_devSeparatorTop = nullptr;
    QWidgetAction* m_sliderAction = nullptr;
    QLabel* m_valueLabel = nullptr;
    QSlider* m_slider = nullptr;

    // Device actions currently inserted between m_status and m_devSeparatorTop.
    QVector<QAction*> m_deviceActions;
};

// A single global controller pointer so the C ABI free functions can reach the
// instance for thread-safe marshalling.
static TrayController* g_ctrl = nullptr;

static QIcon makeIcon() {
    // Self-drawn fallback icon so we never depend on a theme being present.
    QPixmap pm(64, 64);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setBrush(QColor(0x2b, 0x7a, 0xe4));
    p.setPen(Qt::NoPen);
    p.drawRoundedRect(6, 12, 52, 34, 6, 6);
    p.setBrush(QColor(255, 255, 255));
    p.drawRoundedRect(24, 46, 16, 6, 2, 2);
    p.end();
    return QIcon(pm);
}

void TrayController::build() {
    m_menu = new QMenu();
    // CRITICAL: force Qt to render this menu in-process instead of exporting it
    // as a DBusMenu. DBusMenu cannot carry a QSlider; the platform menu would
    // silently drop our QWidgetAction. AA_DontUseNativeMenuBar is about menu
    // bars; for the tray menu we rely on Qt's own popup, which is the default
    // when the menu has embedded widgets — but we set the property explicitly
    // to be safe across platform plugins.
    m_menu->setProperty("_q_platform_MenuNative", false);

    // Header (disabled label).
    m_header = m_menu->addAction(QStringLiteral("AirFry"));
    m_header->setEnabled(false);

    // Status / section line (disabled).
    m_status = m_menu->addAction(QStringLiteral("Scanning…"));
    m_status->setEnabled(false);

    // Separator that device entries are inserted *before*. Device actions get
    // inserted between m_status and this separator.
    m_devSeparatorTop = m_menu->addSeparator();

    // ---- Underscan slider row (the mandatory inline QSlider) ----
    QWidget* row = new QWidget(m_menu);
    QHBoxLayout* lay = new QHBoxLayout(row);
    lay->setContentsMargins(12, 4, 12, 4);
    lay->setSpacing(8);

    QLabel* lbl = new QLabel(QStringLiteral("Underscan"), row);
    m_slider = new QSlider(Qt::Horizontal, row);
    m_slider->setMinimum(0);
    m_slider->setMaximum(15);
    m_slider->setSingleStep(1);
    m_slider->setPageStep(1);
    if (m_initialPct < 0) m_initialPct = 0;
    if (m_initialPct > 15) m_initialPct = 15;
    m_slider->setValue(m_initialPct);
    m_slider->setMinimumWidth(120);

    m_valueLabel = new QLabel(QString::number(m_initialPct) + QStringLiteral("%"), row);
    m_valueLabel->setMinimumWidth(34);

    lay->addWidget(lbl);
    lay->addWidget(m_slider, 1);
    lay->addWidget(m_valueLabel);
    row->setLayout(lay);

    m_sliderAction = new QWidgetAction(m_menu);
    m_sliderAction->setDefaultWidget(row);
    m_menu->addAction(m_sliderAction);

    m_menu->addSeparator();

    QAction* rescan = m_menu->addAction(QStringLiteral("Rescan"));
    QAction* quit = m_menu->addAction(QStringLiteral("Quit"));

    connect(m_slider, &QSlider::valueChanged, this, &TrayController::onSliderChanged);
    connect(rescan, &QAction::triggered, this, &TrayController::onRescan);
    connect(quit, &QAction::triggered, this, &TrayController::onQuit);
    connect(m_menu, &QMenu::aboutToShow, this, &TrayController::onAboutToShow);

    // ---- Tray icon ----
    m_tray = new QSystemTrayIcon(this);
    m_tray->setIcon(makeIcon());
    m_tray->setToolTip(QStringLiteral("AirFry — AirPlay sender"));
    m_tray->setContextMenu(m_menu);
    m_tray->show();
}

void TrayController::onAboutToShow() {
    if (m_cb.on_rescan) m_cb.on_rescan(m_cb.ctx);
}

void TrayController::onSliderChanged(int v) {
    m_valueLabel->setText(QString::number(v) + QStringLiteral("%"));
    if (m_cb.on_underscan) m_cb.on_underscan(m_cb.ctx, v);
}

void TrayController::onRescan() {
    if (m_cb.on_rescan) m_cb.on_rescan(m_cb.ctx);
}

void TrayController::onQuit() {
    if (m_cb.on_quit) m_cb.on_quit(m_cb.ctx);
    QApplication::quit();
}

void TrayController::applyStatus(QString text) {
    if (m_status) m_status->setText(text);
}

void TrayController::applyDevices(QVector<QString> names, QVector<QString> addrs) {
    // Remove old device actions.
    for (QAction* a : m_deviceActions) {
        m_menu->removeAction(a);
        a->deleteLater();
    }
    m_deviceActions.clear();

    const int n = names.size();
    for (int i = 0; i < n; ++i) {
        const QString name = names[i];
        const QString addr = addrs[i];
        QString label = name.isEmpty() ? addr : (name + QStringLiteral("  (") + addr + QStringLiteral(")"));
        QAction* a = new QAction(label, m_menu);
        // Capture addr by value; forward to Rust on trigger.
        AirfryTrayCallbacks cb = m_cb;
        std::string addrStd = addr.toStdString();
        connect(a, &QAction::triggered, this, [cb, addrStd]() {
            if (cb.on_device) cb.on_device(cb.ctx, addrStd.c_str());
        });
        // Insert before the top device separator (i.e. after the status line).
        m_menu->insertAction(m_devSeparatorTop, a);
        m_deviceActions.push_back(a);
    }
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------
extern "C" int airfry_tray_run(const AirfryTrayCallbacks* cb, int initial_pct) {
    static int argc = 1;
    static char argv0[] = "airfry";
    static char* argv[] = { argv0, nullptr };

    QApplication app(argc, argv);
    // Keep running when the menu/popup closes; only Quit ends the loop.
    QApplication::setQuitOnLastWindowClosed(false);

    // Register the metatype used by queued cross-thread invokeMethod calls.
    qRegisterMetaType<QVector<QString>>("QVector<QString>");

    TrayController ctrl(cb, initial_pct);
    g_ctrl = &ctrl;
    ctrl.build();

    if (cb && cb->on_ready) cb->on_ready(cb->ctx);

    int rc = app.exec();
    g_ctrl = nullptr;
    return rc;
}

extern "C" void airfry_tray_set_devices(const char* const* names,
                                        const char* const* addrs, int n) {
    if (!g_ctrl) return;
    QVector<QString> qn, qa;
    qn.reserve(n);
    qa.reserve(n);
    for (int i = 0; i < n; ++i) {
        qn.push_back(QString::fromUtf8(names && names[i] ? names[i] : ""));
        qa.push_back(QString::fromUtf8(addrs && addrs[i] ? addrs[i] : ""));
    }
    QMetaObject::invokeMethod(g_ctrl, "applyDevices", Qt::QueuedConnection,
                              Q_ARG(QVector<QString>, qn),
                              Q_ARG(QVector<QString>, qa));
}

extern "C" void airfry_tray_set_status(const char* text) {
    if (!g_ctrl) return;
    QString t = QString::fromUtf8(text ? text : "");
    QMetaObject::invokeMethod(g_ctrl, "applyStatus", Qt::QueuedConnection,
                              Q_ARG(QString, t));
}

#include "tray.moc"
