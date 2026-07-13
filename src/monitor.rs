//! Live terminal dashboard for soulvpn activity.
//!
//! Keys: q quit · o on · f off · r refresh now · space toggle

use crate::control;
use crate::stats::{format_bytes, format_duration, format_rate, StatusSnapshot};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Sparkline};
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::path::Path;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(250);
const TICK: Duration = Duration::from_millis(500);

struct Rates {
    prev_tx: u64,
    prev_rx: u64,
    prev_at: Instant,
    tx_rate: f64,
    rx_rate: f64,
    tx_hist: Vec<u64>,
    rx_hist: Vec<u64>,
}

impl Rates {
    fn new(snap: &StatusSnapshot) -> Self {
        Self {
            prev_tx: snap.tx_bytes,
            prev_rx: snap.rx_bytes,
            prev_at: Instant::now(),
            tx_rate: 0.0,
            rx_rate: 0.0,
            tx_hist: vec![0; 60],
            rx_hist: vec![0; 60],
        }
    }

    fn update(&mut self, snap: &StatusSnapshot) {
        let now = Instant::now();
        let dt = now.duration_since(self.prev_at).as_secs_f64().max(0.001);
        self.tx_rate = (snap.tx_bytes.saturating_sub(self.prev_tx)) as f64 / dt;
        self.rx_rate = (snap.rx_bytes.saturating_sub(self.prev_rx)) as f64 / dt;
        self.prev_tx = snap.tx_bytes;
        self.prev_rx = snap.rx_bytes;
        self.prev_at = now;

        self.tx_hist.push(self.tx_rate as u64);
        self.rx_hist.push(self.rx_rate as u64);
        if self.tx_hist.len() > 60 {
            self.tx_hist.remove(0);
        }
        if self.rx_hist.len() > 60 {
            self.rx_hist.remove(0);
        }
    }
}

pub async fn run(socket: &Path) -> Result<()> {
    // One probe so we fail before taking over the terminal.
    let first = control::request(socket, "status").await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = ui_loop(&mut terminal, socket, first).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn ui_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    socket: &Path,
    first: StatusSnapshot,
) -> Result<()> {
    let mut rates = Rates::new(&first);
    let mut snap = first;
    let mut last_poll = Instant::now() - TICK;
    let mut err: Option<String> = None;
    let mut msg: Option<String> = None;

    loop {
        if last_poll.elapsed() >= TICK {
            match control::request(socket, "status").await {
                Ok(s) => {
                    rates.update(&s);
                    snap = s;
                    err = None;
                }
                Err(e) => {
                    err = Some(e.to_string());
                }
            }
            last_poll = Instant::now();
        }

        terminal.draw(|f| draw(f, &snap, &rates, err.as_deref(), msg.as_deref()))?;

        if event::poll(POLL)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('o') => {
                        match control::request(socket, "on").await {
                            Ok(s) => {
                                snap = s;
                                msg = Some("tunnel enabled".into());
                                err = None;
                            }
                            Err(e) => err = Some(e.to_string()),
                        }
                    }
                    KeyCode::Char('f') => {
                        match control::request(socket, "off").await {
                            Ok(s) => {
                                snap = s;
                                msg = Some("tunnel disabled".into());
                                err = None;
                            }
                            Err(e) => err = Some(e.to_string()),
                        }
                    }
                    KeyCode::Char(' ') => {
                        let op = if snap.enabled { "off" } else { "on" };
                        match control::request(socket, op).await {
                            Ok(s) => {
                                let enabled = s.enabled;
                                snap = s;
                                msg = Some(format!(
                                    "tunnel {}",
                                    if enabled { "enabled" } else { "disabled" }
                                ));
                                err = None;
                            }
                            Err(e) => err = Some(e.to_string()),
                        }
                    }
                    KeyCode::Char('r') => {
                        last_poll = Instant::now() - TICK;
                        msg = Some("refresh".into());
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn draw(
    f: &mut ratatui::Frame,
    snap: &StatusSnapshot,
    rates: &Rates,
    err: Option<&str>,
    msg: Option<&str>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(f.area());

    let state_color = if snap.enabled {
        Color::Green
    } else {
        Color::Red
    };
    let state = if snap.enabled { " ON " } else { " OFF " };
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " soulvpn ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:?}", snap.role).to_uppercase(),
            Style::default().fg(Color::White),
        ),
        Span::raw("  "),
        Span::styled(
            state,
            Style::default()
                .bg(state_color)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  pid {}  tun {}", snap.pid, snap.tun_name)),
    ]))
    .block(Block::default().borders(Borders::ALL).title("status"));
    f.render_widget(title, chunks[0]);

    let info = Paragraph::new(vec![
        Line::from(format!("endpoint   {}", snap.endpoint)),
        Line::from(format!("address    {}", snap.address)),
        Line::from(format!(
            "uptime     {}",
            format_duration(Duration::from_secs(snap.uptime_secs))
        )),
        Line::from(format!("sessions   {}", snap.active_sessions)),
        Line::from(format!(
            "handshakes ok={}  fail={}",
            snap.handshakes_ok, snap.handshakes_fail
        )),
        Line::from(format!(
            "errors     encrypt={}  decrypt={}",
            snap.encrypt_errors, snap.decrypt_errors
        )),
    ])
    .block(Block::default().borders(Borders::ALL).title("session"));
    f.render_widget(info, chunks[1]);

    draw_traffic(f, chunks[2], "tx ↑", snap.tx_packets, snap.tx_bytes, rates.tx_rate, &rates.tx_hist, Color::Yellow);
    draw_traffic(f, chunks[3], "rx ↓", snap.rx_packets, snap.rx_bytes, rates.rx_rate, &rates.rx_hist, Color::Magenta);

    let max_r = rates.tx_rate.max(rates.rx_rate).max(1.0);
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("link load (relative)"))
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(((rates.tx_rate + rates.rx_rate) / (2.0 * max_r)).clamp(0.0, 1.0))
        .label(format!(
            "↑ {}  ↓ {}",
            format_rate(rates.tx_rate),
            format_rate(rates.rx_rate)
        ));
    f.render_widget(gauge, chunks[4]);

    let footer = if let Some(e) = err {
        Line::from(Span::styled(
            format!(" error: {e} "),
            Style::default().fg(Color::Red),
        ))
    } else if let Some(m) = msg {
        Line::from(Span::styled(
            format!(" {m} "),
            Style::default().fg(Color::Green),
        ))
    } else {
        Line::from(Span::styled(
            " q quit · space toggle · o on · f off · r refresh ",
            Style::default().fg(Color::DarkGray),
        ))
    };
    f.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL).title("keys")),
        chunks[5],
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_traffic(
    f: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    packets: u64,
    bytes: u64,
    rate: f64,
    hist: &[u64],
    color: Color,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(10)])
        .split(area);

    let text = Paragraph::new(vec![
        Line::from(Span::styled(
            title,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("{packets} pkts")),
        Line::from(format_bytes(bytes)),
        Line::from(format_rate(rate)),
    ])
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(text, cols[0]);

    let spark = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title("rate"))
        .data(hist)
        .style(Style::default().fg(color));
    f.render_widget(spark, cols[1]);
}
