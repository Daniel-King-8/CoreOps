use super::*;
use crate::rdp::{kind, HEADER_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn header(bytes: &[u8], at: usize) -> (u8, u16, u16, u16, u16, u16, u16) {
    let u = |i: usize| u16::from_le_bytes([bytes[at + i], bytes[at + i + 1]]);
    (bytes[at], u(1), u(3), u(5), u(7), u(9), u(11))
}

/// A server that speaks just enough RFB 3.8: no password, a 4×2 desktop,
/// then one raw rectangle and one copy, and a clipboard text.
async fn fake_server(listener: TcpListener) {
    let (mut s, _) = listener.accept().await.unwrap();
    s.write_all(b"RFB 003.008\n").await.unwrap();
    let mut version = [0u8; 12];
    s.read_exact(&mut version).await.unwrap();
    // One security type: None.
    s.write_all(&[1, 1]).await.unwrap();
    let mut chosen = [0u8; 1];
    s.read_exact(&mut chosen).await.unwrap();
    assert_eq!(chosen[0], 1);
    s.write_all(&0u32.to_be_bytes()).await.unwrap();
    // ClientInit: the shared flag.
    let mut shared = [0u8; 1];
    s.read_exact(&mut shared).await.unwrap();

    // ServerInit: 4×2, 32 bpp true colour, little-endian, BGRX, name "t".
    let mut init = Vec::new();
    init.extend_from_slice(&4u16.to_be_bytes());
    init.extend_from_slice(&2u16.to_be_bytes());
    init.extend_from_slice(&[32, 24, 0, 1]);
    init.extend_from_slice(&255u16.to_be_bytes());
    init.extend_from_slice(&255u16.to_be_bytes());
    init.extend_from_slice(&255u16.to_be_bytes());
    init.extend_from_slice(&[16, 8, 0, 0, 0, 0]);
    init.extend_from_slice(&1u32.to_be_bytes());
    init.push(b't');
    s.write_all(&init).await.unwrap();

    // What the client says next (pixel format, encodings, a request) is
    // read in the background and dropped; this server talks regardless.
    let (mut r, mut w) = s.into_split();
    tokio::spawn(async move {
        let mut sink = [0u8; 1024];
        while r.read(&mut sink).await.is_ok_and(|n| n > 0) {}
    });

    // FramebufferUpdate with two rectangles: 2×1 raw at (1,0), then a
    // copy of that to (1,1). The client asked for R, G, B, X bytes.
    let mut u = vec![0u8, 0];
    u.extend_from_slice(&2u16.to_be_bytes());
    for v in [1u16, 0, 2, 1] {
        u.extend_from_slice(&v.to_be_bytes());
    }
    u.extend_from_slice(&0i32.to_be_bytes());
    u.extend_from_slice(&[0x11, 0x22, 0x33, 0, 0xAA, 0xBB, 0xCC, 0]);
    for v in [1u16, 1, 2, 1] {
        u.extend_from_slice(&v.to_be_bytes());
    }
    u.extend_from_slice(&1i32.to_be_bytes());
    for v in [1u16, 0] {
        u.extend_from_slice(&v.to_be_bytes());
    }
    w.write_all(&u).await.unwrap();

    // ServerCutText "hi".
    let mut cut = vec![3u8, 0, 0, 0];
    cut.extend_from_slice(&2u32.to_be_bytes());
    cut.extend_from_slice(b"hi");
    w.write_all(&cut).await.unwrap();

    // Stay up until the client is done.
    tokio::time::sleep(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_login_and_updates_reach_the_screen() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(fake_server(listener));

    let client = open("127.0.0.1", port, String::new()).await.unwrap();
    let mut screen = Screen::default();
    let mut text = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while text.is_none() {
        let event = tokio::time::timeout_at(deadline, client.recv_event()).await.expect("events in time").unwrap();
        if let Some(VncEvent::Text(t)) = draw(&mut screen, event, "t") {
            text = Some(t);
        }
    }
    assert_eq!(text.as_deref(), Some("hi"));
    assert_eq!(screen.size(), (4, 2));

    let bytes = screen.take();
    assert_eq!(header(&bytes, 0), (kind::FULL, 0, 0, 4, 2, 4, 2));
    let px = |x: usize, y: usize| &bytes[HEADER_LEN + (y * 4 + x) * 4..HEADER_LEN + (y * 4 + x) * 4 + 4];
    // The raw rectangle, made opaque, and its copy one row down.
    assert_eq!(px(1, 0), &[0x11, 0x22, 0x33, 0xff]);
    assert_eq!(px(2, 0), &[0xAA, 0xBB, 0xCC, 0xff]);
    assert_eq!(px(1, 1), &[0x11, 0x22, 0x33, 0xff]);
    assert_eq!(px(2, 1), &[0xAA, 0xBB, 0xCC, 0xff]);
    assert_eq!(px(0, 0), &[0, 0, 0, 0xff]);

    let _ = client.close().await;
    server.abort();
}

#[test]
fn copies_that_overlap_move_the_right_pixels() {
    let mut screen = Screen::default();
    screen.resize(1, 4);
    let column: Vec<u8> = (1..=4).flat_map(|v| [v, v, v, 0]).collect();
    screen.blit_rgba(0, 0, 1, 4, &column);
    // Down by one, overlapping: rows 0..3 to 1..4.
    screen.copy_rect((0, 1), (0, 0), 1, 3);
    let bytes = screen.take();
    let rows: Vec<u8> = (0..4).map(|y| bytes[HEADER_LEN + y * 4]).collect();
    assert_eq!(rows, [1, 1, 2, 3]);

    // And back up.
    screen.copy_rect((0, 0), (0, 1), 1, 3);
    let bytes = screen.take();
    let (_, x, y, w, h, ..) = header(&bytes, 0);
    assert_eq!((x, y, w, h), (0, 0, 1, 3));
    let rows: Vec<u8> = (0..3).map(|y| bytes[HEADER_LEN + y * 4]).collect();
    assert_eq!(rows, [1, 2, 3]);
}

#[test]
fn updates_off_the_desktop_are_skipped() {
    let mut screen = Screen::default();
    screen.resize(4, 4);
    let _ = screen.take();
    screen.blit_rgba(3, 3, 2, 1, &[0; 8]);
    screen.blit_rgba(0, 0, 2, 2, &[0; 4]); // short of pixels
    screen.copy_rect((3, 0), (0, 0), 2, 1);
    assert!(!screen.pending());
}

#[test]
fn a_cursor_with_no_size_hides_it() {
    let mut screen = Screen::default();
    screen.resize(4, 4);
    let _ = screen.take();
    let empty = vnc::Rect { x: 0, y: 0, width: 0, height: 0 };
    assert!(draw(&mut screen, VncEvent::SetCursor(empty, Vec::new()), "t").is_none());
    assert_eq!(screen.take(), [kind::POINTER_HIDDEN]);

    let shape = vnc::Rect { x: 1, y: 0, width: 1, height: 1 };
    draw(&mut screen, VncEvent::SetCursor(shape, vec![1, 2, 3, 255]), "t");
    let bytes = screen.take();
    assert_eq!(bytes[0], kind::POINTER_SHAPE);
    assert_eq!(&bytes[1..9], &[1, 0, 1, 0, 1, 0, 0, 0]);
    assert_eq!(&bytes[9..], &[1, 2, 3, 255]);
}

#[test]
fn clipboard_text_keeps_to_ascii() {
    assert_eq!(latin1("a\r\nb"), "a\nb");
    assert_eq!(latin1("café λ"), "caf? ?");
}

#[test]
fn a_broken_jpeg_is_an_error_not_a_panic() {
    assert!(decode_jpeg(&[0xFF, 0xD8, 0x00], 2, 2).is_err());
}

#[test]
fn mouse_actions_parse() {
    assert_eq!(MouseAction::parse("wheel").unwrap(), MouseAction::Wheel);
    assert!(MouseAction::parse("drag").is_err());
}

/// Against a real server: `REACH_VNC_TEST=host:port REACH_VNC_PASSWORD=…
/// cargo test --lib vnc::tests::live -- --ignored --nocapture`. Pulls as the
/// pump does for five seconds and reports how many distinct pictures came.
#[tokio::test]
#[ignore = "needs a VNC server"]
async fn live_frame_rate() {
    let addr = std::env::var("REACH_VNC_TEST").expect("REACH_VNC_TEST=host:port");
    let (host, port) = addr.rsplit_once(':').unwrap();
    let password = std::env::var("REACH_VNC_PASSWORD").unwrap_or_default();
    let client = open(host, port.parse().unwrap(), password).await.unwrap();

    let mut screen = Screen::default();
    let mut pull = tokio::time::interval(PULL_EVERY);
    let (mut frames, mut bytes, mut first) = (0u32, 0usize, None);
    let start = tokio::time::Instant::now();
    let end = start + Duration::from_secs(5);
    loop {
        tokio::select! {
            event = client.recv_event() => {
                draw(&mut screen, event.unwrap(), "live");
            }
            _ = pull.tick() => {
                if screen.pending() {
                    let out = screen.take();
                    if first.is_none() {
                        first = Some(start.elapsed());
                    }
                    frames += 1;
                    bytes += out.len();
                }
                client.input(X11Event::Refresh).await.unwrap();
            }
            _ = tokio::time::sleep_until(end) => break,
        }
    }
    println!(
        "desktop {:?}; first picture after {:?}; {frames} pictures in 5 s ({:.1}/s); {:.1} MB to the webview",
        screen.size(),
        first,
        f64::from(frames) / 5.0,
        bytes as f64 / 1e6
    );
    assert!(frames > 0);
    let _ = client.close().await;
}
