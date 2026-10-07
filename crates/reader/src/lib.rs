#![forbid(unsafe_code)]
//! patanyx-reader: the article inside a web page, as plain typed blocks.
//!
//! Reader View reads the page the server sent (the same main-resource bytes
//! page integrity reads), never the live DOM: no script runs in the page to
//! produce it, so it works in a tab where script is off, and nothing the
//! page's own code adds after load can steer it.
//!
//! The output is deliberately NOT HTML. An [`Article`] is a list of
//! [`Block`]s holding plain strings, and the browser UI renders each one
//! with `textContent`. Page markup therefore never reaches the privileged
//! chrome webview, whatever the page contains: there is nothing to sanitize
//! because nothing executable survives extraction.
//!
//! # Method
//!
//! A small Readability-style scorer:
//! 1. Drop what is never article text (script, style, forms, navigation,
//!    hidden elements) and containers whose class or id reads as page
//!    furniture (comments, sidebars, share bars, cookie notices).
//! 2. Score each paragraph-like element by length and commas, credit its
//!    parent fully and its grandparent by half, weight by class/id hints,
//!    and discount by link density.
//! 3. Take the best container plus any sibling that scores close to it.
//! 4. Walk the result into blocks.
//!
//! # Hostile input
//!
//! Input is capped ([`MAX_INPUT_BYTES`]) and so is nesting depth, checked
//! by a linear scan before parsing (see `nesting`); the parser is
//! html5ever's, which recovers from any malformed markup. Every walk this crate does is either
//! iterative or depth-capped ([`MAX_DEPTH`]), so deep nesting cannot
//! overflow the stack. Output is capped too ([`MAX_BLOCKS`],
//! [`MAX_OUTPUT_CHARS`]) and marked `truncated` when a cap is hit.

mod charset;
mod depth;

use dom_query::{Document, NodeRef};
use serde::Serialize;
use std::collections::HashMap;
use thiserror::Error;

/// Largest page Reader View will parse. Smaller than the 16 MiB the
/// main-resource capture buffers: building a tree costs far more memory
/// than hashing bytes, and no article needs more than this.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Deepest element nesting walked when emitting blocks.
pub const MAX_DEPTH: usize = 128;
/// Most nodes returned for one article: every block counts one, and every
/// list item counts one more, because each becomes an element the chrome
/// creates (review R-003: a list counted as one block let 300,000
/// items through).
pub const MAX_BLOCKS: usize = 4000;
/// Longest title, byline or site name kept, in characters.
pub const MAX_META_CHARS: usize = 300;
/// Most characters of text returned for one article.
pub const MAX_OUTPUT_CHARS: usize = 1_000_000;
/// An article with less text than this is not worth a Reader View; the
/// page is a list, a form, an app shell, or a page built by script.
pub const MIN_ARTICLE_CHARS: usize = 250;

#[derive(Debug, Error, PartialEq)]
pub enum ReaderError {
    #[error("page too large for Reader View: {len} bytes (max {max})")]
    InputTooLarge { len: usize, max: usize },
    #[error("page encoding not supported: {0}")]
    UnsupportedEncoding(String),
    /// Nested more deeply than any article does; refused before parsing
    /// because parse time grows with the square of the depth.
    #[error("page nests too deeply for Reader View")]
    TooComplex,
    #[error("no article found on this page")]
    NoArticle,
}

/// One unit of article content. Every string is plain text.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Block {
    Heading { level: u8, text: String },
    Para { text: String },
    List { ordered: bool, items: Vec<String> },
    Quote { text: String },
    /// Preformatted: whitespace is significant and preserved.
    Pre { text: String },
    /// What an image would have shown, from its caption or alt text. Reader
    /// View loads no images, so this is all that stands in for one.
    Caption { text: String },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Article {
    pub title: String,
    pub byline: Option<String>,
    pub site: Option<String>,
    pub blocks: Vec<Block>,
    /// True when an output cap cut the article short.
    pub truncated: bool,
}

/// Extract the article from a page's raw response bytes.
pub fn extract(html: &[u8]) -> Result<Article, ReaderError> {
    if html.len() > MAX_INPUT_BYTES {
        return Err(ReaderError::InputTooLarge {
            len: html.len(),
            max: MAX_INPUT_BYTES,
        });
    }
    let text = charset::decode(html)?;
    // Parsed with the nesting guard: refused as soon as the tree the parser
    // builds passes the limit (see depth.rs).
    let doc = depth::parse_bounded(&text).ok_or(ReaderError::TooComplex)?;

    let mut meta_cut = false;
    let mut cap = |s: String| -> String {
        if s.chars().count() > MAX_META_CHARS {
            meta_cut = true;
            s.chars().take(MAX_META_CHARS).collect()
        } else {
            s
        }
    };
    let site = meta_content(&doc, "meta[property='og:site_name']").map(&mut cap);
    let title = cap(pick_title(
        meta_content(&doc, "meta[property='og:title']")
            .or_else(|| first_text(&doc, "title")),
        first_text(&doc, "h1"),
    ));
    let byline = meta_content(&doc, "meta[name='author']")
        .or_else(|| first_text(&doc, "[rel='author'], .byline, .author"))
        .filter(|b| b.chars().count() <= 100);

    strip_non_content(&doc);
    // The byline is shown once, from metadata, above the article; the
    // page's own byline line would repeat it as the first paragraph.
    if byline.is_some() {
        doc.select(".byline, [rel='author'], [itemprop='author']").remove();
    }

    let root = best_root(&doc).ok_or(ReaderError::NoArticle)?;
    let mut out = Emitter {
        // The metadata is output too, and counts against the same budget.
        out_chars: title.chars().count()
            + site.as_ref().map_or(0, |s| s.chars().count())
            + byline.as_ref().map_or(0, |s| s.chars().count()),
        truncated: meta_cut,
        ..Emitter::default()
    };
    for node in &root {
        out.walk(node, 0);
    }
    let mut blocks = out.blocks;
    // The page title usually repeats as the first heading.
    if let Some(Block::Heading { text, .. }) = blocks.first() {
        if same_words(text, &title) {
            blocks.remove(0);
        }
    }
    if out.body_chars < MIN_ARTICLE_CHARS {
        return Err(ReaderError::NoArticle);
    }
    Ok(Article {
        title,
        byline,
        site,
        blocks,
        truncated: out.truncated,
    })
}

// --- Metadata -------------------------------------------------------------

fn meta_content(doc: &Document, sel: &str) -> Option<String> {
    let s = doc.select_single(sel);
    let node = s.nodes().first()?;
    let v = collapse(&node.attr("content")?);
    (!v.is_empty()).then_some(v)
}

fn first_text(doc: &Document, sel: &str) -> Option<String> {
    let s = doc.select_single(sel);
    let node = s.nodes().first()?;
    let v = collapse(&node.text());
    (!v.is_empty()).then_some(v)
}

/// The article's own headline when the document title is that headline
/// plus decoration ("Headline | Site Name"), else the document title.
fn pick_title(doc_title: Option<String>, h1: Option<String>) -> String {
    match (doc_title, h1) {
        (Some(t), Some(h)) if same_words(&h, &t) => h,
        (Some(t), _) => t,
        (None, Some(h)) => h,
        (None, None) => String::new(),
    }
}

// --- Cleaning -------------------------------------------------------------

/// Elements that never carry article text.
const DROP_TAGS: &str = "script, style, noscript, template, iframe, object, embed, svg, \
    canvas, math, form, button, input, select, textarea, nav, aside, footer, dialog, \
    head, link, meta, [hidden], [aria-hidden='true'], [role='navigation'], \
    [role='complementary'], [role='banner'], [role='contentinfo'], [role='dialog']";

const UNLIKELY: &[&str] = &[
    "comment", "sidebar", "footer", "masthead", "menu", "share", "social", "promo",
    "related", "advert", "sponsor", "cookie", "consent", "banner", "popup", "modal",
    "subscribe", "newsletter", "breadcrumb", "pagination", "skip", "outbrain", "taboola",
];
const LIKELY: &[&str] = &[
    "article", "body", "content", "entry", "main", "post", "story", "text", "prose",
];

fn strip_non_content(doc: &Document) {
    doc.select(DROP_TAGS).remove();
    // Collect first, then remove: removing while iterating would skip nodes.
    // One linear pass over the tree. A descendant-combinator selector such
    // as "body *" re-walks every element's ancestors, which is quadratic on
    // a deeply nested hostile page.
    let unlikely: Vec<NodeRef> = doc
        .root()
        .descendants_it()
        .filter(|n| n.is_element())
        .filter(|n| {
            let name = n.node_name().unwrap_or_default();
            if matches!(&*name, "body" | "article" | "main" | "a") {
                return false;
            }
            let hint = hint_of(n);
            !hint.is_empty()
                && UNLIKELY.iter().any(|u| hint.contains(u))
                && !LIKELY.iter().any(|l| hint.contains(l))
        })
        .collect();
    for n in unlikely {
        n.remove_from_parent();
    }
    // Inline display:none is how many pages hide print-only or template
    // copies of the text.
    let hidden: Vec<NodeRef> = doc
        .select("[style]")
        .nodes()
        .iter()
        .filter(|n| {
            let style: String = n
                .attr("style")
                .unwrap_or_default()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_ascii_lowercase();
            style.contains("display:none") || style.contains("visibility:hidden")
        })
        .cloned()
        .collect();
    for n in hidden {
        n.remove_from_parent();
    }
}

fn hint_of(n: &NodeRef) -> String {
    let mut s = n.attr("class").map(|c| c.to_string()).unwrap_or_default();
    s.push(' ');
    s.push_str(&n.attr("id").unwrap_or_default());
    s.to_ascii_lowercase()
}

fn class_weight(n: &NodeRef) -> f64 {
    let hint = hint_of(n);
    let mut w = 0.0;
    if LIKELY.iter().any(|l| hint.contains(l)) {
        w += 25.0;
    }
    if UNLIKELY.iter().any(|u| hint.contains(u)) {
        w -= 25.0;
    }
    w
}

// --- Scoring --------------------------------------------------------------

fn text_len(n: &NodeRef) -> usize {
    collapse(&n.text()).chars().count()
}

fn link_density(n: &NodeRef) -> f64 {
    let total = text_len(n);
    if total == 0 {
        return 1.0;
    }
    let linked: usize = n
        .descendants_it()
        .filter(|d| d.node_name().as_deref() == Some("a"))
        .map(|a| text_len(&a))
        .sum();
    (linked as f64 / total as f64).min(1.0)
}

/// The containers that hold the article, in document order: the best
/// scoring element plus siblings that score close to it.
fn best_root<'a>(doc: &'a Document) -> Option<Vec<NodeRef<'a>>> {
    let mut scores: HashMap<dom_query::NodeId, (NodeRef<'a>, f64)> = HashMap::new();
    for p in doc.select("p, pre, td, blockquote, li, div").nodes() {
        // A div holding only inline content is a paragraph in all but
        // name: many blogs never write a <p>.
        if p.node_name().as_deref() == Some("div")
            && p.element_children().iter().any(|c| {
                matches!(
                    c.node_name().as_deref(),
                    Some(
                        "p" | "div" | "ul" | "ol" | "table" | "pre" | "blockquote" | "section"
                            | "article" | "figure" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
                    )
                )
            })
        {
            continue;
        }
        let len = text_len(p);
        if len < 25 {
            continue;
        }
        let commas = p.text().matches([',', '\u{3001}', '\u{FF0C}']).count();
        let score = 1.0 + commas as f64 + (len as f64 / 100.0).min(3.0);
        let mut ancestors = p.ancestors_it(Some(2));
        for (share, anc) in [(1.0, ancestors.next()), (0.5, ancestors.next())] {
            let Some(anc) = anc else { break };
            if !anc.is_element() {
                break;
            }
            let entry = scores
                .entry(anc.id)
                .or_insert_with(|| (anc, class_weight(&anc) + tag_weight(&anc)));
            entry.1 += score * share;
        }
    }
    let (top, top_score) = scores
        .values()
        .map(|(n, s)| (*n, s * (1.0 - link_density(n))))
        .max_by(|a, b| a.1.total_cmp(&b.1))?;

    let Some(parent) = top.parent() else {
        return Some(vec![top]);
    };
    let threshold = (top_score * 0.2).max(10.0);
    let mut picked = Vec::new();
    for sib in parent.children_it(false) {
        if sib.id == top.id {
            picked.push(sib);
            continue;
        }
        if !sib.is_element() {
            continue;
        }
        let sib_score = scores
            .get(&sib.id)
            .map_or(0.0, |(n, s)| s * (1.0 - link_density(n)));
        let is_good_para = sib.node_name().as_deref() == Some("p")
            && text_len(&sib) > 80
            && link_density(&sib) < 0.25;
        if sib_score >= threshold || is_good_para {
            picked.push(sib);
        }
    }
    Some(picked)
}

fn tag_weight(n: &NodeRef) -> f64 {
    match n.node_name().as_deref() {
        Some("article") => 10.0,
        Some("main") | Some("div") => 5.0,
        Some("section") | Some("pre") | Some("td") | Some("blockquote") => 3.0,
        Some("ol") | Some("ul") | Some("dl") | Some("form") => -3.0,
        Some(h) if h.len() == 2 && h.starts_with('h') => -5.0,
        _ => 0.0,
    }
}

// --- Emitting blocks ------------------------------------------------------

#[derive(Default)]
struct Emitter {
    blocks: Vec<Block>,
    /// Body text only (no headings or captions): decides whether the page
    /// has an article at all.
    body_chars: usize,
    /// Every character returned, metadata included: the output cap.
    out_chars: usize,
    /// Elements the chrome will create: blocks plus list items.
    nodes: usize,
    /// Something was left out: reported to the reader.
    truncated: bool,
    /// The output budget is spent: stop walking. Separate from `truncated`,
    /// which a cut title or one over-deep branch also sets without the
    /// rest of the article being out of room.
    full: bool,
    /// Loose inline text found directly inside a container, gathered into
    /// one paragraph until the next block-level element.
    pending: String,
}

impl Emitter {
    fn push(&mut self, mut block: Block) {
        // A list is cut item by item to whatever budget remains, so one huge
        // list cannot take the whole allowance or be dropped wholesale.
        if let Block::List { items, .. } = &mut block {
            let mut nodes_left = MAX_BLOCKS.saturating_sub(self.nodes + 1);
            let mut chars_left = MAX_OUTPUT_CHARS.saturating_sub(self.out_chars);
            let mut kept = Vec::new();
            for item in items.drain(..) {
                let n = item.chars().count();
                if nodes_left == 0 || n > chars_left {
                    self.truncated = true;
                    self.full = true;
                    break;
                }
                nodes_left -= 1;
                chars_left -= n;
                kept.push(item);
            }
            *items = kept;
        }
        let (len, nodes) = match &block {
            Block::Heading { text, .. }
            | Block::Para { text }
            | Block::Quote { text }
            | Block::Pre { text }
            | Block::Caption { text } => (text.chars().count(), 1),
            Block::List { items, .. } => (
                items.iter().map(|i| i.chars().count()).sum(),
                1 + items.len(),
            ),
        };
        if len == 0 {
            return;
        }
        if self.nodes + nodes > MAX_BLOCKS || self.out_chars + len > MAX_OUTPUT_CHARS {
            self.truncated = true;
            self.full = true;
            return;
        }
        self.nodes += nodes;
        self.out_chars += len;
        // Headings and captions are labels, not body text; counting them
        // would let a page of headings pass as an article.
        if !matches!(block, Block::Heading { .. } | Block::Caption { .. }) {
            self.body_chars += len;
        }
        self.blocks.push(block);
    }

    fn flush(&mut self) {
        let text = collapse(&std::mem::take(&mut self.pending));
        if !text.is_empty() {
            self.push(Block::Para { text });
        }
    }

    fn walk(&mut self, n: &NodeRef, depth: usize) {
        if self.full {
            return;
        }
        if n.is_text() {
            self.pending.push_str(&n.text());
            return;
        }
        if !n.is_element() {
            return;
        }
        if depth >= MAX_DEPTH {
            self.truncated = true;
            return;
        }
        let name = n.node_name().unwrap_or_default();
        match &*name {
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                self.flush();
                let level = name.as_bytes()[1] - b'0';
                self.push(Block::Heading {
                    level,
                    text: collapse(&n.text()),
                });
            }
            "p" => {
                self.flush();
                let text = inline_text(n, depth, &mut self.truncated);
                self.push(Block::Para { text });
            }
            "pre" => {
                self.flush();
                let text = n.text().trim_matches('\n').to_string();
                self.push(Block::Pre { text });
            }
            "blockquote" => {
                self.flush();
                let text = inline_text(n, depth, &mut self.truncated);
                self.push(Block::Quote { text });
            }
            "ul" | "ol" => {
                self.flush();
                let items: Vec<String> = n
                    .element_children()
                    .iter()
                    .filter(|c| c.node_name().as_deref() == Some("li"))
                    .map(|li| inline_text(li, depth, &mut self.truncated))
                    .filter(|t| !t.is_empty())
                    .collect();
                self.push(Block::List {
                    ordered: &*name == "ol",
                    items,
                });
            }
            "img" => {
                if let Some(alt) = n.attr("alt") {
                    self.flush();
                    self.push(Block::Caption { text: collapse(&alt) });
                }
            }
            "figure" => {
                self.flush();
                let caption = n
                    .descendants_it()
                    .find(|d| d.node_name().as_deref() == Some("figcaption"))
                    .map(|c| collapse(&c.text()))
                    .filter(|t| !t.is_empty())
                    .or_else(|| {
                        n.descendants_it()
                            .find(|d| d.node_name().as_deref() == Some("img"))
                            .and_then(|i| i.attr("alt"))
                            .map(|a| collapse(&a))
                    });
                if let Some(text) = caption {
                    self.push(Block::Caption { text });
                }
            }
            "tr" => {
                self.flush();
                let cells: Vec<String> = n
                    .element_children()
                    .iter()
                    .map(|c| collapse(&c.text()))
                    .filter(|t| !t.is_empty())
                    .collect();
                self.push(Block::Para {
                    text: cells.join(" | "),
                });
            }
            "br" => self.pending.push('\n'),
            "hr" => self.flush(),
            "a" | "span" | "em" | "strong" | "b" | "i" | "u" | "code" | "small" | "sub"
            | "sup" | "mark" | "abbr" | "cite" | "q" | "time" | "s" | "del" | "ins"
            | "kbd" | "var" | "bdi" | "bdo" | "font" => {
                self.pending.push_str(&n.text());
            }
            _ => {
                // A container (div, section, article, td, li outside a
                // list, ...): its block children break paragraphs, its
                // inline content gathers into one.
                for c in n.children_it(false) {
                    self.walk(&c, depth + 1);
                }
                if is_block_container(&name) {
                    self.flush();
                }
            }
        }
    }
}

fn is_block_container(name: &str) -> bool {
    matches!(
        name,
        "div" | "section" | "article" | "main" | "header" | "li" | "dd" | "dt" | "td"
            | "th" | "table" | "tbody" | "thead" | "caption" | "details" | "summary"
            | "address" | "center"
    )
}

/// The text of an element with `<br>` and block boundaries kept as line
/// breaks and all other whitespace collapsed. Sets `truncated` when nesting
/// past MAX_DEPTH cut text off (review R-008: that used to be silent).
fn inline_text(n: &NodeRef, depth: usize, truncated: &mut bool) -> String {
    let mut raw = String::new();
    collect_inline(n, depth, &mut raw, truncated);
    raw.split('\n')
        .map(collapse)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_inline(n: &NodeRef, depth: usize, out: &mut String, truncated: &mut bool) {
    if depth >= MAX_DEPTH {
        *truncated = true;
        return;
    }
    for c in n.children_it(false) {
        if c.is_text() {
            out.push_str(&c.text());
        } else if c.is_element() {
            let name = c.node_name().unwrap_or_default();
            if &*name == "br" {
                out.push('\n');
            } else if is_block_name(&name) {
                // Two paragraphs inside a quote, or a nested list, must not
                // run together (review R-010).
                out.push('\n');
                collect_inline(&c, depth + 1, out, truncated);
                out.push('\n');
            } else {
                collect_inline(&c, depth + 1, out, truncated);
            }
        }
    }
}

fn is_block_name(name: &str) -> bool {
    is_block_container(name)
        || matches!(
            name,
            "p" | "ul" | "ol" | "blockquote" | "pre" | "figure" | "figcaption" | "h1" | "h2"
                | "h3" | "h4" | "h5" | "h6" | "hr" | "dl"
        )
}

/// Collapse runs of whitespace to one space and trim. Non-breaking spaces
/// count as whitespace here: in running text they only ever separate words.
fn collapse(s: &str) -> String {
    s.split(|c: char| c.is_whitespace() || c == '\u{00A0}')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn same_words(a: &str, b: &str) -> bool {
    let a = collapse(a).to_lowercase();
    let b = collapse(b).to_lowercase();
    !a.is_empty() && (a == b || b.starts_with(&a))
}

#[cfg(test)]
mod tests;
