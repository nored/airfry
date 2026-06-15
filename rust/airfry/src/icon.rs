//! Self-drawn tray icons (no theme dependency).
//!
//! The macOS **Screen Mirroring** glyph: two overlapping landscape rounded
//! rectangles, the front layered over the back (mirrored — front lower-LEFT).
//! Rendered with 4× supersampled anti-aliasing for crisp, professional edges at
//! several sizes (the host picks the best). White idle, blue while mirroring.

use ksni::Icon;

/// Idle colour: white.
const WHITE: (u8, u8, u8) = (0xF2, 0xF2, 0xF2);
/// Streaming colour: AirFry blue.
const BLUE: (u8, u8, u8) = (0x2F, 0x88, 0xF0);
/// Supersampling factor (NxN coverage per output pixel → anti-aliased edges).
const SS: i32 = 4;
/// Sizes to provide; the SNI host chooses the closest to the panel size.
const SIZES: [i32; 4] = [22, 32, 44, 64];

/// White (idle) tray icons.
pub fn idle() -> Vec<Icon> {
    SIZES.iter().map(|&s| render(s, WHITE)).collect()
}

/// Blue (mirroring) tray icons.
pub fn streaming() -> Vec<Icon> {
    SIZES.iter().map(|&s| render(s, BLUE)).collect()
}

/// True if point (px,py) is inside the rounded rectangle [x0,x1]×[y0,y1] with
/// corner radius r (all in float pixel units).
fn in_rrect(px: f32, py: f32, x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> bool {
    if px < x0 || px > x1 || py < y0 || py > y1 {
        return false;
    }
    let cx = px.clamp(x0 + r, x1 - r);
    let cy = py.clamp(y0 + r, y1 - r);
    let (dx, dy) = (px - cx, py - cy);
    dx * dx + dy * dy <= r * r
}

/// Render the glyph at `size` px in `color`, ARGB32 (network byte order: A,R,G,B
/// per pixel), with SS× supersampled anti-aliasing.
fn render(size: i32, color: (u8, u8, u8)) -> Icon {
    let (r, g, b) = color;
    let s = size as f32;

    // Geometry as fractions of the icon size.
    let rw = 0.50 * s; // rectangle width
    let rh = 0.38 * s; // rectangle height
    let rad = 0.085 * s; // corner radius
    let stroke = (0.075 * s).max(1.6); // outline thickness
    let dx = 0.22 * s; // horizontal offset between the two rects
    let dy = 0.20 * s; // vertical offset

    // Centre the (rw+dx)×(rh+dy) bounding box.
    let lm = (s - (rw + dx)) * 0.5;
    let tm = (s - (rh + dy)) * 0.5;
    // Back: upper-right. Front: lower-left, layered on top.
    let back = (lm + dx, tm, lm + dx + rw, tm + rh);
    let front = (lm, tm + dy, lm + rw, tm + dy + rh);

    // Outline coverage of a rounded rect (between the outer edge and the inner
    // edge shrunk by `stroke`).
    let outline = |px: f32, py: f32, q: (f32, f32, f32, f32)| -> bool {
        let outer = in_rrect(px, py, q.0, q.1, q.2, q.3, rad);
        let inner = in_rrect(
            px,
            py,
            q.0 + stroke,
            q.1 + stroke,
            q.2 - stroke,
            q.3 - stroke,
            (rad - stroke).max(0.0),
        );
        outer && !inner
    };
    // The front rect (expanded by ~one stroke) occludes the back, leaving a
    // clean gap between them — the layered look.
    let front_occludes = |px: f32, py: f32| -> bool {
        in_rrect(
            px,
            py,
            front.0 - stroke,
            front.1 - stroke,
            front.2 + stroke,
            front.3 + stroke,
            rad + stroke,
        )
    };
    let inside = |px: f32, py: f32| -> bool {
        outline(px, py, front) || (outline(px, py, back) && !front_occludes(px, py))
    };

    let w = size;
    let h = size;
    let mut data = vec![0u8; (w * h * 4) as usize];
    let inv = 1.0 / SS as f32;
    for oy in 0..h {
        for ox in 0..w {
            let mut cov = 0u32;
            for sy in 0..SS {
                for sx in 0..SS {
                    let px = ox as f32 + (sx as f32 + 0.5) * inv;
                    let py = oy as f32 + (sy as f32 + 0.5) * inv;
                    if inside(px, py) {
                        cov += 1;
                    }
                }
            }
            if cov == 0 {
                continue;
            }
            let alpha = (cov * 255 / (SS * SS) as u32) as u8;
            let i = ((oy * w + ox) * 4) as usize;
            data[i] = alpha;
            data[i + 1] = r;
            data[i + 2] = g;
            data[i + 3] = b;
        }
    }

    Icon {
        width: w,
        height: h,
        data,
    }
}
