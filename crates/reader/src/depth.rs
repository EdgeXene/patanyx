//! The nesting guard: the depth the HTML parser actually builds, measured
//! while it builds it.
//!
//! html5ever's tree builder does work proportional to its stack of open
//! elements for each tag it inserts, so a page that nests very deeply costs
//! time quadratic in that depth: measured on this crate, 20,000 nested divs
//! (100 KB) took 0.55 s to parse and 100,000 (500 KB) took 13 s. No article
//! nests anywhere near that deep, so such a page is refused.
//!
//! The first guard was a pre-scan that modelled the parser's stack from the
//! raw bytes. Review found the model and the parser disagreeing in ways a page
//! can choose: a self-closed `<svg/>` sent the scan looking for `</svg>` to
//! the end of the input, and `</div>` was taken to close a div across an
//! `<object>`, which the parser refuses to do. Each let 100,000 levels through.
//! A faithful model of the tree builder is a second tree builder, and the next
//! rule it misses is the next bypass (the parser also reopens formatting
//! elements and nests template contents in their own fragment).
//!
//! So this measures the parser instead. A sink wrapper walks up from every
//! node the parser attaches and records the deepest it has seen; the input is
//! fed in chunks, and parsing stops after the first chunk that takes the tree
//! past [`MAX_NESTING`]. Whatever rules the parser follows, the depth it
//! builds is the depth checked. Every element on the parser's stack is an
//! ancestor of the element being inserted (or, when a table forces a node out
//! in front of it, a sibling of one), so the stack is never more than about
//! twice the measured depth. The most a page can add past the limit is one
//! chunk, and the walk itself stops just past the limit, so the cost of a
//! refused page is bounded however it is built.
//!
//! Depth is not the only way to make the parser work. Formatting elements a
//! paragraph closed stay "active" and are reopened in every later paragraph,
//! so 400 open `<b>`s followed by 100,000 `<p>x</p>` ask for 40 million
//! elements in under 1 MB while the tree stays about 400 deep (review round 3,
//! R-001: that page ran for minutes and grew without bound). So element
//! creation has a budget too, proportional to the input: an element written
//! in the markup costs at least three bytes (`<a>`), so a page whose
//! elements outnumber half its bytes is one the parser is multiplying. The
//! reopened copies carry their attributes, so attributes count too (review
//! round 4, R-001: one `<b>` with 10,000 attributes reopened 10,000 times),
//! and once a page is over budget the copies are dropped as they arrive.
//! Their length counts as well (final review, R-001: one `<b>` with a 1 MiB
//! attribute reopened in 100,000 paragraphs stayed within the count while
//! handing the cleaning pass 100 GiB of attribute text): the attribute text
//! the parser hands over may not exceed the page's own size, which is the
//! most the markup itself can contain.
//!
//! Some of the parser's work creates nothing to count: it compares each
//! attribute of a tag with every earlier one in the same tag, so one tag with
//! a million attributes is half a trillion comparisons before any element
//! exists (review round 4, R-002). So parsing also has a time limit, checked
//! after every chunk. That one depends on the machine; a page that takes
//! longer than that to parse is not one anybody can read in Reader View.

use std::borrow::Cow;
use std::cell::{Cell, Ref, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use dom_query::{Document, NodeId};
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeBuilderOpts, TreeSink};
use html5ever::{parse_document, Attribute, ParseOpts, QualName};

/// Deepest nesting allowed. Real pages rarely pass 100; the headroom keeps
/// generated markup (deep table layouts, nested component wrappers)
/// readable while keeping the parser's worst case to a fraction of a second.
pub(crate) const MAX_NESTING: usize = 512;

/// Input fed to the parser between checks. Small enough that the overrun
/// past either limit is cheap (one chunk of reopened formatting elements is
/// at most a few hundred thousand), large enough that the per-chunk overhead
/// is noise.
const CHUNK_BYTES: usize = 4 * 1024;

/// Elements plus attributes the parser may create: half of one per input
/// byte (an element costs at least three bytes of markup, an attribute at
/// least two), plus headroom for the elements it adds itself (html, head,
/// body, tbody).
fn element_budget(input_len: usize) -> usize {
    input_len / 2 + 10_000
}

/// Longest a parse may run. The worst page within the other limits (8 MiB,
/// nested 500 deep) parses in about 1.2 s in a release build.
const PARSE_TIME_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Parse `html` into a document, or `None` if the tree it builds nests deeper
/// than [`MAX_NESTING`], it creates more than its budget of elements and
/// attributes or of attribute text, or it takes longer than
/// [`PARSE_TIME_LIMIT`].
pub(crate) fn parse_bounded(html: &str) -> Option<Document> {
    let deepest = Rc::new(Cell::new(0usize));
    let created = Rc::new(Cell::new(0usize));
    let budget = element_budget(html.len());
    let attr_bytes = Rc::new(Cell::new(0usize));
    let attr_byte_budget = html.len() + 64 * 1024;
    let sink = DepthSink {
        inner: Document::default(),
        deepest: deepest.clone(),
        created: created.clone(),
        budget,
        attr_bytes: attr_bytes.clone(),
        attr_byte_budget,
        template_of: RefCell::new(HashMap::new()),
    };
    let started = std::time::Instant::now();
    let over = || {
        deepest.get() > MAX_NESTING
            || created.get() > budget
            || attr_bytes.get() > attr_byte_budget
            || started.elapsed() > PARSE_TIME_LIMIT
    };
    let opts = ParseOpts {
        tokenizer: Default::default(),
        tree_builder: TreeBuilderOpts {
            scripting_enabled: false,
            ..Default::default()
        },
    };
    let mut parser = parse_document(sink, opts);
    let mut rest = html;
    while !rest.is_empty() {
        let mut cut = rest.len().min(CHUNK_BYTES);
        while !rest.is_char_boundary(cut) {
            cut += 1;
        }
        let (chunk, tail) = rest.split_at(cut);
        parser.process(StrTendril::from_slice(chunk));
        if over() {
            return None;
        }
        rest = tail;
    }
    let doc = parser.finish();
    (!over()).then_some(doc)
}

/// dom_query's own sink, plus a running maximum of the depth of every node
/// attached to the tree.
struct DepthSink {
    inner: Document,
    deepest: Rc<Cell<usize>>,
    /// Elements and attributes created so far, checked against the input's
    /// budget.
    created: Rc<Cell<usize>>,
    budget: usize,
    /// Bytes of attribute names and values handed over so far, checked
    /// against the page's size.
    attr_bytes: Rc<Cell<usize>>,
    attr_byte_budget: usize,
    /// Template contents are a parentless fragment in this tree; walking up
    /// from inside one continues at the template that owns it, or nesting
    /// `<template>`s would start the count again at every level.
    template_of: RefCell<HashMap<NodeId, NodeId>>,
}

impl DepthSink {
    /// Depth of `node`, walking up through parents (and from template
    /// contents to their template), stopping one past the limit.
    fn depth_of(&self, node: &NodeId) -> usize {
        let tree = &self.inner.tree;
        let templates = self.template_of.borrow();
        let mut depth = 0;
        let mut at = *node;
        while depth <= MAX_NESTING {
            match tree.parent_of(&at) {
                Some(parent) => at = parent.id,
                None => match templates.get(&at) {
                    Some(template) => at = *template,
                    None => break,
                },
            }
            depth += 1;
        }
        depth
    }

    fn note(&self, child: &NodeOrText<NodeId>) {
        if let NodeOrText::AppendNode(node) = child {
            let depth = self.depth_of(node);
            if depth > self.deepest.get() {
                self.deepest.set(depth);
            }
        }
    }
}

fn node_of(child: &NodeOrText<NodeId>) -> NodeOrText<NodeId> {
    match child {
        NodeOrText::AppendNode(node) => NodeOrText::AppendNode(*node),
        NodeOrText::AppendText(text) => NodeOrText::AppendText(text.clone()),
    }
}

impl TreeSink for DepthSink {
    type ElemName<'a> = Ref<'a, QualName>;
    type Output = Document;
    type Handle = NodeId;

    fn finish(self) -> Document {
        self.inner
    }

    fn parse_error(&self, msg: Cow<'static, str>) {
        self.inner.parse_error(msg)
    }

    fn get_document(&self) -> NodeId {
        self.inner.get_document()
    }

    fn get_template_contents(&self, target: &NodeId) -> NodeId {
        let contents = self.inner.get_template_contents(target);
        self.template_of.borrow_mut().insert(contents, *target);
        contents
    }

    fn set_quirks_mode(&self, mode: QuirksMode) {
        self.inner.set_quirks_mode(mode)
    }

    fn same_node(&self, x: &NodeId, y: &NodeId) -> bool {
        self.inner.same_node(x, y)
    }

    fn elem_name<'a>(&'a self, target: &'a NodeId) -> Ref<'a, QualName> {
        self.inner.elem_name(target)
    }

    fn create_element(&self, name: QualName, attrs: Vec<Attribute>, flags: ElementFlags) -> NodeId {
        let created = self.created.get() + 1 + attrs.len();
        self.created.set(created);
        let bytes = attrs
            .iter()
            .map(|a| a.name.local.len() + a.value.len())
            .fold(self.attr_bytes.get(), usize::saturating_add);
        self.attr_bytes.set(bytes);
        // Over either budget the page is already refused at the end of this
        // chunk; until then, attribute copies are dropped instead of stored.
        let attrs = if created > self.budget || bytes > self.attr_byte_budget {
            Vec::new()
        } else {
            attrs
        };
        self.inner.create_element(name, attrs, flags)
    }

    fn create_comment(&self, text: StrTendril) -> NodeId {
        self.inner.create_comment(text)
    }

    fn create_pi(&self, target: StrTendril, data: StrTendril) -> NodeId {
        self.inner.create_pi(target, data)
    }

    fn append(&self, parent: &NodeId, child: NodeOrText<NodeId>) {
        let seen = node_of(&child);
        self.inner.append(parent, child);
        self.note(&seen);
    }

    fn append_before_sibling(&self, sibling: &NodeId, child: NodeOrText<NodeId>) {
        let seen = node_of(&child);
        self.inner.append_before_sibling(sibling, child);
        self.note(&seen);
    }

    fn append_based_on_parent_node(
        &self,
        element: &NodeId,
        prev_element: &NodeId,
        child: NodeOrText<NodeId>,
    ) {
        let seen = node_of(&child);
        self.inner
            .append_based_on_parent_node(element, prev_element, child);
        self.note(&seen);
    }

    fn append_doctype_to_document(
        &self,
        name: StrTendril,
        public_id: StrTendril,
        system_id: StrTendril,
    ) {
        self.inner
            .append_doctype_to_document(name, public_id, system_id)
    }

    fn add_attrs_if_missing(&self, target: &NodeId, attrs: Vec<Attribute>) {
        self.inner.add_attrs_if_missing(target, attrs)
    }

    fn remove_from_parent(&self, target: &NodeId) {
        self.inner.remove_from_parent(target)
    }

    fn reparent_children(&self, node: &NodeId, new_parent: &NodeId) {
        self.inner.reparent_children(node, new_parent)
    }

    fn is_mathml_annotation_xml_integration_point(&self, handle: &NodeId) -> bool {
        self.inner.is_mathml_annotation_xml_integration_point(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn depth(html: &str) -> Option<usize> {
        let deepest = Rc::new(Cell::new(0usize));
        let sink = DepthSink {
            inner: Document::default(),
            deepest: deepest.clone(),
            created: Rc::new(Cell::new(0)),
            budget: usize::MAX,
            attr_bytes: Rc::new(Cell::new(0)),
            attr_byte_budget: usize::MAX,
            template_of: RefCell::new(HashMap::new()),
        };
        let _ = parse_document(sink, ParseOpts::default()).one(html);
        let d = deepest.get();
        (d <= MAX_NESTING).then_some(d)
    }

    #[test]
    fn measures_what_the_parser_builds() {
        // document > html > body > div > section > div
        assert_eq!(depth("<div><section><div>x</div></section></div>"), Some(5));
    }

    #[test]
    fn unclosed_paragraphs_and_items_do_not_deepen() {
        // document > html > body > ul > li > p, however many there are.
        let page = "<ul>".to_string() + &"<li>item<p>para".repeat(5000) + "</ul>";
        assert_eq!(depth(&page), Some(5));
    }

    #[test]
    fn a_slash_on_a_div_does_not_close_it() {
        assert_eq!(depth("<div/><div/><div/>"), Some(5));
    }

    #[test]
    fn svg_children_are_measured_inside_the_svg() {
        let page = "<div><svg>".to_string() + &"<path d='M0 0'/>".repeat(2000) + "</svg></div>";
        assert_eq!(depth(&page), Some(5));
    }

    #[test]
    fn template_contents_count_from_their_template() {
        // document > html > head > template > [contents] > template >
        // [contents] > div: each contents fragment counts as a level, which
        // only ever over-counts.
        assert_eq!(depth("<template><template><div>x</div></template></template>"), Some(7));
    }

    #[test]
    fn parsing_stops_soon_after_the_limit() {
        let page = "<div>".repeat(100_000);
        assert!(parse_bounded(&page).is_none());
    }

    #[test]
    fn a_page_of_nothing_but_elements_fits_the_budget() {
        // The densest real markup: three bytes per element.
        let page = "<i>".repeat(200_000) + &"</i>".repeat(200_000);
        let flat = "<a></a>".repeat(300_000);
        assert!(parse_bounded(&flat).is_some(), "flat elements are within budget");
        assert!(parse_bounded(&page).is_none(), "but 200,000 deep is still refused for depth");
    }

    #[test]
    fn a_page_within_the_limit_parses_whole() {
        let page = "<div>".repeat(400) + "<p>deep text</p>" + &"</div>".repeat(400);
        let doc = parse_bounded(&page).expect("400 deep is within the limit");
        assert_eq!(doc.select("p").text().to_string(), "deep text");
    }
}
