//! utility/audit_report_002_pdf.rs

use std::io;

use chrono::{DateTime, Utc};
use pdf_writer::{Content, Name, Pdf, Rect, Ref, Str};

use crate::utility::{
    alpha_001_global_configuration::GlobalConfiguration, audit_report_001_hub::AuditReport,
};

/* ───── page/typography constants ───── */
const PAGE_W: f32 = 595.0;
const PAGE_H: f32 = 842.0;
const MARGIN_L: f32 = 50.0;
const MARGIN_T: f32 = 40.0;
const MARGIN_B: f32 = 40.0;

const FONT_SIZE: f32 = 10.0;
const LEADING: f32 = 13.0;
const CHARS_PER_LINE: usize = 80;

/* ───────────────────────────────────────────────────────────── */

#[allow(clippy::float_arithmetic)]
pub fn build_pdf(
    report: &AuditReport,
    generated_ts: &DateTime<Utc>,
    export_ts: &DateTime<Utc>,
    maybe_fps: Option<(&str, &str)>,
    total_tx: u64,
) -> io::Result<Vec<u8>> {
    /* helpers -------------------------------------------------- */

    fn wrap(s: &str) -> impl Iterator<Item = &str> {
        struct Wrap<'a> {
            s: &'a str,
            start: usize,
            empty_done: bool,
        }

        impl<'a> Iterator for Wrap<'a> {
            type Item = &'a str;

            fn next(&mut self) -> Option<Self::Item> {
                // Special-case empty: emit one empty segment.
                if self.s.is_empty() {
                    if self.empty_done {
                        return None;
                    }
                    self.empty_done = true;
                    return Some("");
                }

                if self.start >= self.s.len() {
                    return None;
                }

                // Work only with a safe subslice from a known char boundary.
                let tail = self.s.get(self.start..)?;
                let mut end = self.s.len();

                // Find end byte index after CHARS_PER_LINE chars (or end of string).
                for (chars, (i, _)) in tail.char_indices().enumerate() {
                    if chars == CHARS_PER_LINE {
                        end = self.start.checked_add(i).unwrap_or(self.s.len());
                        break;
                    }
                }

                let seg = self.s.get(self.start..end)?;
                self.start = end;
                Some(seg)
            }
        }

        Wrap {
            s,
            start: 0,
            empty_done: false,
        }
    }

    fn write_line(c: &mut Content, txt: &str, x: f32, y: f32) {
        c.begin_text();
        c.set_font(Name(b"F1"), FONT_SIZE);
        c.set_leading(LEADING);
        c.set_text_matrix([1.0, 0.0, 0.0, 1.0, x, y]);
        c.show(Str(txt.as_bytes()));
        c.end_text();
    }

    // truncate long hex fields for display (head 32 + tail 32)
    fn preview_32_32(s: &str) -> String {
        const HEAD: usize = 32;
        const TAIL: usize = 32;

        let bytes = s.as_bytes();
        if bytes.len() <= HEAD + TAIL + 3 {
            return s.to_string();
        }

        let start_tail = bytes.len().saturating_sub(TAIL);

        // Hex strings are ASCII, so this is safe and preserves identical output for valid hex.
        let head_bytes = bytes.get(..HEAD).unwrap_or(bytes);
        let tail_bytes = bytes.get(start_tail..).unwrap_or(bytes);

        let head = core::str::from_utf8(head_bytes).unwrap_or(s);
        let tail = core::str::from_utf8(tail_bytes).unwrap_or(s);

        format!("{head}...{tail}")
    }

    // compute fingerprint = blake3(signature_bytes) from hex, safe fallback on decode errors
    fn fp_blake3_from_hex(hex_str: &str) -> Option<String> {
        match hex::decode(hex_str) {
            Ok(bytes) => Some(blake3::hash(&bytes).to_hex().to_string()),
            Err(_) => None,
        }
    }

    /* PDF skeleton --------------------------------------------- */
    let mut pdf = Pdf::new();
    let catalog_id = Ref::new(1);
    let pages_id = Ref::new(2);
    let font_id = Ref::new(3);

    pdf.catalog(catalog_id).pages(pages_id);
    pdf.type1_font(font_id).base_font(Name(b"Courier"));

    /* pagination ----------------------------------------------- */
    let usable_h = PAGE_H - MARGIN_T - MARGIN_B;
    let lines_per_page_f = (usable_h / LEADING).floor();

    let lines_per_page = if !lines_per_page_f.is_finite() || lines_per_page_f <= 0.0 {
        0usize
    } else {
        match format!("{lines_per_page_f:.0}").parse::<usize>() {
            Ok(v) => v,
            Err(_) => usize::MAX,
        }
    };

    let mut y = PAGE_H - MARGIN_T;
    let mut lines_used = 0usize;
    let mut next_id = 4;
    let mut page_refs = Vec::<Ref>::new();
    let mut content = Content::new();

    /* ───── metadata header ───── */
    let chain_id = GlobalConfiguration::COIN_NAME;
    let guardian_id = GlobalConfiguration::GENESIS_VALIDATOR;
    let block_span = report.blocks.len() as u64;

    write_line(
        &mut content,
        &format!("Chain ID              : {chain_id}"),
        MARGIN_L,
        y,
    );
    y -= LEADING;
    lines_used = lines_used.saturating_add(1);

    for (i, seg) in wrap(guardian_id).enumerate() {
        let lbl = if i == 0 {
            "Guardian ID          : "
        } else {
            "                       "
        };
        write_line(&mut content, &format!("{lbl}{seg}"), MARGIN_L, y);
        y -= LEADING;
        lines_used = lines_used.saturating_add(1);
    }

    write_line(
        &mut content,
        &format!("Report time (UTC)     : {}", generated_ts.timestamp()),
        MARGIN_L,
        y,
    );
    y -= LEADING;
    write_line(
        &mut content,
        &format!("Export  time (UTC)    : {}", export_ts.timestamp()),
        MARGIN_L,
        y,
    );
    y -= LEADING;
    write_line(
        &mut content,
        &format!("Block span (count)    : {block_span}"),
        MARGIN_L,
        y,
    );
    y -= LEADING;
    write_line(
        &mut content,
        &format!("Total transactions    : {total_tx}"),
        MARGIN_L,
        y,
    );
    y -= LEADING * 2.0;
    lines_used = lines_used.saturating_add(6);

    /* header summary (after meta) ---------------- */
    let total = report.blocks.len();
    let start_ts = report.blocks.first().map(|b| b.timestamp).unwrap_or(0);
    let end_ts = report.blocks.last().map(|b| b.timestamp).unwrap_or(0);
    let duration = end_ts.saturating_sub(start_ts);

    let avg_size = if total == 0 {
        0
    } else {
        let denom = u64::try_from(total).unwrap_or(u64::MAX);
        report
            .blocks
            .iter()
            .map(|b| b.size)
            .sum::<u64>()
            .checked_div(denom)
            .unwrap_or(0)
    };

    write_line(
        &mut content,
        &format!(
            "Total blocks: {total}   Range: {start_ts}–{end_ts}   Duration: {duration}s   Avg size: {avg_size} bytes"
        ),
        MARGIN_L,
        y,
    );
    y -= LEADING;
    write_line(
        &mut content,
        &format!("Generated {} UTC", generated_ts),
        MARGIN_L,
        y,
    );
    y -= LEADING * 2.0;
    lines_used = lines_used.saturating_add(3);

    /* per-block detail loop ------------------------------------ */
    for blk in &report.blocks {
        /* estimate lines needed */
        let mut need = 2usize;
        need = need.saturating_add(wrap(&blk.current_hash).count());
        need = need.saturating_add(wrap(&blk.previous_hash).count());
        need = need.saturating_add(wrap(&blk.merkle_root).count());
        // CHANGED: signature is now preview + (len + fp) instead of full wrap
        need = need.saturating_add(wrap(&preview_32_32(&blk.guardian_sig)).count());
        need = need.saturating_add(2);

        if lines_used.saturating_add(need) > lines_per_page {
            flush_page(
                &mut pdf,
                content,
                &mut page_refs,
                pages_id,
                font_id,
                &mut next_id,
            );
            content = Content::new();
            y = PAGE_H - MARGIN_T;
            lines_used = 0;
        }

        /* block header */
        write_line(
            &mut content,
            &format!(
                "Block #{:<6} | ts {:<12} | size {:<8} bytes",
                blk.index, blk.timestamp, blk.size
            ),
            MARGIN_L,
            y,
        );
        y -= LEADING;
        lines_used = lines_used.saturating_add(1);

        for (label, val) in [
            ("curr", &blk.current_hash),
            ("prev", &blk.previous_hash),
            ("mrkl", &blk.merkle_root),
            ("sig ", &blk.guardian_sig),
        ] {
            if label == "sig " {
                let preview = preview_32_32(val);

                for (i, seg) in wrap(&preview).enumerate() {
                    let prefix = if i == 0 {
                        format!("   {label}: ")
                    } else {
                        "         ".into()
                    };
                    write_line(&mut content, &format!("{prefix}{seg}"), MARGIN_L, y);
                    y -= LEADING;
                    lines_used = lines_used.saturating_add(1);
                }

                // len line
                write_line(
                    &mut content,
                    &format!("         (sig len: {} hex chars)", val.len()),
                    MARGIN_L,
                    y,
                );
                y -= LEADING;
                lines_used = lines_used.saturating_add(1);

                // fp line
                let fp =
                    fp_blake3_from_hex(val).unwrap_or_else(|| "<hex decode failed>".to_string());
                for seg in wrap(&fp) {
                    write_line(
                        &mut content,
                        &format!("         fp(blake3(sig_bytes)): {seg}"),
                        MARGIN_L,
                        y,
                    );
                    y -= LEADING;
                    lines_used = lines_used.saturating_add(1);
                }
            } else {
                for (i, seg) in wrap(val).enumerate() {
                    let prefix = if i == 0 {
                        format!("   {label}: ")
                    } else {
                        "         ".into()
                    };
                    write_line(&mut content, &format!("{prefix}{seg}"), MARGIN_L, y);
                    y -= LEADING;
                    lines_used = lines_used.saturating_add(1);
                }
            }
        }
        y -= LEADING;
        lines_used = lines_used.saturating_add(1);
    }

    /* fingerprints --------------------------------------------- */
    if let Some((data_fp, pdf_fp)) = maybe_fps {
        // required lines: heading + two digest lines (wrapped)
        let extra_lines = 1usize
            .saturating_add(wrap(data_fp).count())
            .saturating_add(wrap(pdf_fp).count());

        if lines_used.saturating_add(extra_lines) > lines_per_page {
            flush_page(
                &mut pdf,
                content,
                &mut page_refs,
                pages_id,
                font_id,
                &mut next_id,
            );
            content = Content::new();
            y = PAGE_H - MARGIN_T;
        }

        write_line(&mut content, "Digital Fingerprints (BLAKE3):", MARGIN_L, y);
        y -= LEADING;
        for seg in wrap(data_fp) {
            write_line(
                &mut content,
                &format!("  Data (canonical snapshot): {seg}"),
                MARGIN_L,
                y,
            );
            y -= LEADING;
        }
        for seg in wrap(pdf_fp) {
            write_line(
                &mut content,
                &format!("  PDF  (this file)        : {seg}"),
                MARGIN_L,
                y,
            );
            y -= LEADING;
        }
    }

    /* final flush --------------------------------------------- */
    flush_page(
        &mut pdf,
        content,
        &mut page_refs,
        pages_id,
        font_id,
        &mut next_id,
    );

    /* commit page tree ---------------------------------------- */
    let total_pages = i32::try_from(page_refs.len()).unwrap_or(i32::MAX);
    pdf.pages(pages_id).kids(page_refs).count(total_pages);

    Ok(pdf.finish())
}

/* helper: takes ownership of Content, finishes it, and attaches page */
fn flush_page(
    pdf: &mut Pdf,
    content: Content,
    page_refs: &mut Vec<Ref>,
    pages_id: Ref,
    font_id: Ref,
    next_id: &mut i32,
) {
    let page_id = Ref::new(*next_id);
    *next_id = next_id.checked_add(1).unwrap_or(i32::MAX);
    let cont_id = Ref::new(*next_id);
    *next_id = next_id.checked_add(1).unwrap_or(i32::MAX);

    pdf.page(page_id)
        .parent(pages_id)
        .media_box(Rect::new(0.0, 0.0, PAGE_W, PAGE_H))
        .contents(cont_id)
        .resources()
        .fonts()
        .pair(Name(b"F1"), font_id);

    let stream = content.finish();
    pdf.stream(cont_id, &stream);
    page_refs.push(page_id);
}
