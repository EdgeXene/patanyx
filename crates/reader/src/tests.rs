use super::*;

const LOREM: &str = "The committee met on Tuesday to review the proposal, and after a long \
    discussion of costs, timing and the effect on residents, it voted to send the plan \
    back for another round of public comment before any decision is made.";

fn article_page(body: &str) -> String {
    format!(
        "<!doctype html><html><head><title>Council delays vote | Example News</title>\
         <meta property=\"og:site_name\" content=\"Example News\">\
         <meta name=\"author\" content=\"Sam Rivera\"></head><body>\
         <nav class=\"site-nav\"><a href=\"/\">Home</a><a href=\"/world\">World</a></nav>\
         <article class=\"story\"><h1>Council delays vote</h1>{body}</article>\
         <aside class=\"sidebar\"><p>Most read: something else entirely, with commas, and more.</p></aside>\
         <footer><p>Copyright Example News, all rights reserved, everywhere.</p></footer>\
         </body></html>"
    )
}

fn texts(a: &Article) -> String {
    serde_json::to_string(&a.blocks).unwrap()
}

#[test]
fn news_article_keeps_body_and_drops_furniture() {
    let page = article_page(&format!(
        "<p>{LOREM}</p><h2>What happens next</h2><p>{LOREM}</p>\
         <ul><li>First point</li><li>Second point</li></ul>\
         <blockquote>We need more time, the chair said.</blockquote>"
    ));
    let a = extract(page.as_bytes()).unwrap();
    // The headline, not the tab title with the site name appended.
    assert_eq!(a.title, "Council delays vote");
    assert_eq!(a.site.as_deref(), Some("Example News"));
    assert_eq!(a.byline.as_deref(), Some("Sam Rivera"));
    let t = texts(&a);
    assert!(t.contains("committee met on Tuesday"));
    assert!(t.contains("What happens next"));
    assert!(t.contains("Second point"));
    assert!(t.contains("We need more time"));
    assert!(!t.contains("Most read"), "sidebar leaked: {t}");
    assert!(!t.contains("Copyright"), "footer leaked: {t}");
    assert!(!t.contains("World"), "nav leaked: {t}");
    assert!(!a.truncated);
    // The repeated title heading is dropped from the body.
    assert!(!matches!(a.blocks.first(), Some(Block::Heading { text, .. }) if text == "Council delays vote"));
}

#[test]
fn blog_with_divs_and_loose_text_is_found() {
    let page = format!(
        "<html><body><div id=\"header\"><a href=\"/\">My blog</a></div>\
         <div class=\"post-content\"><div>{LOREM}<br>{LOREM}</div><div>{LOREM}</div></div>\
         <div class=\"comments\"><p>Great post, thanks, really, truly, deeply.</p></div></body></html>"
    );
    let a = extract(page.as_bytes()).unwrap();
    let t = texts(&a);
    assert!(t.contains("committee met"));
    assert!(!t.contains("Great post"), "comments leaked: {t}");
}

#[test]
fn docs_page_keeps_code_whitespace() {
    let page = article_page(&format!(
        "<p>{LOREM}</p><pre><code>fn main() {{\n    println!(\"hi\");\n}}</code></pre><p>{LOREM}</p>"
    ));
    let a = extract(page.as_bytes()).unwrap();
    assert!(a.blocks.iter().any(
        |b| matches!(b, Block::Pre { text } if text.contains("\n    println!(\"hi\");\n"))
    ));
}

#[test]
fn navigation_only_page_has_no_article() {
    let page = "<html><body><nav><ul><li><a href=a>One</a></li><li><a href=b>Two</a></li></ul></nav>\
                <div class=menu><a href=c>Three</a></div><p>Short.</p></body></html>";
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::NoArticle));
}

#[test]
fn script_shell_page_has_no_article() {
    let page = "<html><body><div id=root></div><script>render()</script></body></html>";
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::NoArticle));
}

#[test]
fn hostile_markup_yields_only_plain_text() {
    let page = article_page(&format!(
        "<p>{LOREM}<script>alert(1)</script><img src=x onerror=alert(2) alt=\"chart of votes\"></p>\
         <style>p{{color:red}}</style><p onclick=\"steal()\">{LOREM}<iframe src=//evil></iframe></p>\
         <p>&lt;script&gt;alert(3)&lt;/script&gt; is shown as text, not run.</p>"
    ));
    let a = extract(page.as_bytes()).unwrap();
    let t = texts(&a);
    assert!(!t.contains("alert(1)"));
    assert!(!t.contains("alert(2)"));
    assert!(!t.contains("color:red"));
    assert!(!t.contains("steal"));
    assert!(!t.contains("evil"));
    // Escaped markup in the article is text, and stays text.
    assert!(t.contains("<script>alert(3)</script> is shown as text"));
}

#[test]
fn hidden_text_is_not_read() {
    let page = article_page(&format!(
        "<p>{LOREM}</p><p style=\"display: none\">secret hidden words here</p>\
         <p hidden>also hidden</p><p aria-hidden=\"true\">aria hidden</p><p>{LOREM}</p>"
    ));
    let t = texts(&extract(page.as_bytes()).unwrap());
    assert!(!t.contains("secret hidden"));
    assert!(!t.contains("also hidden"));
    assert!(!t.contains("aria hidden"));
}

#[test]
fn named_entities_decode_once() {
    let page = article_page(&format!(
        "<p>{LOREM} Caf&eacute; owners &mdash; and residents &ndash; agreed. \
         The literal text &amp;eacute; stays escaped.</p><p>{LOREM}</p>"
    ));
    let t = texts(&extract(page.as_bytes()).unwrap());
    assert!(t.contains("Caf\u{e9} owners \u{2014} and residents \u{2013} agreed."), "{t}");
    assert!(t.contains("The literal text &eacute; stays escaped."), "{t}");
}

#[test]
fn windows_1252_page_reads_correctly() {
    let mut page = b"<html><head><meta charset=windows-1252><title>T</title></head><body><article><p>".to_vec();
    page.extend_from_slice(LOREM.as_bytes());
    page.extend_from_slice(b" \x93Caf\xe9\x94 \x97 na\xefve.</p><p>");
    page.extend_from_slice(LOREM.as_bytes());
    page.extend_from_slice(b"</p></article></body></html>");
    let t = texts(&extract(&page).unwrap());
    assert!(t.contains("\u{201C}Caf\u{e9}\u{201D} \u{2014} na\u{ef}ve."), "{t}");
}

#[test]
fn unsupported_encoding_is_reported() {
    let page = format!("<meta charset=\"euc-kr\"><article><p>{LOREM}</p></article>");
    assert_eq!(
        extract(page.as_bytes()),
        Err(ReaderError::UnsupportedEncoding("euc-kr".into()))
    );
}

#[test]
fn oversized_input_is_refused_before_parsing() {
    let big = vec![b'a'; MAX_INPUT_BYTES + 1];
    assert!(matches!(
        extract(&big),
        Err(ReaderError::InputTooLarge { .. })
    ));
}

#[test]
fn hostile_deep_nesting_is_refused_before_parsing() {
    let depth = 20_000;
    let mut page = String::from("<html><body><article>");
    page.push_str(&"<div>".repeat(depth));
    page.push_str(&format!("<p>{LOREM}</p><p>{LOREM}</p>"));
    page.push_str(&"</div>".repeat(depth));
    page.push_str("</article></body></html>");
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
}

#[test]
fn generated_markup_nested_400_deep_still_reads() {
    let depth = 400;
    let mut page = String::from("<html><body><article>");
    page.push_str(&"<div>".repeat(depth));
    page.push_str(&format!("<p>{LOREM}</p><p>{LOREM}</p>"));
    page.push_str(&"</div>".repeat(depth));
    page.push_str("</article></body></html>");
    let a = extract(page.as_bytes()).unwrap();
    assert!(texts(&a).contains("committee met"));
}

#[test]
fn many_paragraphs_are_capped_and_marked() {
    let mut body = String::new();
    for _ in 0..(MAX_BLOCKS + 50) {
        body.push_str(&format!("<p>{LOREM}</p>"));
    }
    let page = article_page(&body);
    let a = extract(page.as_bytes()).unwrap();
    assert!(a.truncated);
    assert!(a.blocks.len() <= MAX_BLOCKS);
}

#[test]
fn figure_and_alt_become_captions() {
    let page = article_page(&format!(
        "<p>{LOREM}</p><figure><img src=a.jpg alt=\"alt text\"><figcaption>The council chamber</figcaption></figure>\
         <p>{LOREM}</p><img src=b.jpg alt=\"A map of the ward\">"
    ));
    let a = extract(page.as_bytes()).unwrap();
    assert!(a.blocks.contains(&Block::Caption { text: "The council chamber".into() }));
    // An image standing on its own keeps its alt text as the caption.
    assert!(a.blocks.contains(&Block::Caption { text: "A map of the ward".into() }), "{:?}", a.blocks);
}

#[test]
fn serialized_shape_is_stable() {
    let b = Block::Heading { level: 2, text: "x".into() };
    assert_eq!(serde_json::to_string(&b).unwrap(), r#"{"kind":"heading","level":2,"text":"x"}"#);
    let l = Block::List { ordered: true, items: vec!["a".into()] };
    assert_eq!(serde_json::to_string(&l).unwrap(), r#"{"kind":"list","ordered":true,"items":["a"]}"#);
}

#[test]
fn byline_line_is_not_repeated_as_a_paragraph() {
    let page = article_page(&format!(
        "<p class=\"byline\">By Sam Rivera, staff writer</p><p>{LOREM}</p><p>{LOREM}</p>"
    ));
    let a = extract(page.as_bytes()).unwrap();
    assert_eq!(a.byline.as_deref(), Some("Sam Rivera"));
    assert!(!texts(&a).contains("staff writer"), "{}", texts(&a));
}

#[test]
fn byline_element_is_used_when_there_is_no_author_meta() {
    let page = format!(
        "<html><head><title>T</title></head><body><article><h1>T</h1>\
         <p class=\"byline\">By Lee Chan</p><p>{LOREM}</p><p>{LOREM}</p></article></body></html>"
    );
    let a = extract(page.as_bytes()).unwrap();
    assert_eq!(a.byline.as_deref(), Some("By Lee Chan"));
    assert!(!texts(&a).contains("By Lee Chan"));
}

#[test]
fn a_title_unrelated_to_the_headline_is_kept() {
    assert_eq!(pick_title(Some("Front page".into()), Some("Weather".into())), "Front page");
    assert_eq!(pick_title(None, Some("Weather".into())), "Weather");
}

// ---- review 2026-10-06 (R-001 .. R-010), reproduced before fixing ----

#[test]
fn r001_self_closing_divs_still_count_as_nesting() {
    let page = format!("<article><p>{LOREM}</p>{}<p>{LOREM}</p></article>", "<div/>".repeat(20_000));
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
}

#[test]
fn r001_unmatched_end_tags_do_not_reduce_nesting() {
    let page = format!("<article><p>{LOREM}</p>{}<p>{LOREM}</p></article>", "<div></x>".repeat(20_000));
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
}

#[test]
fn r003_list_items_count_against_the_block_budget() {
    let items = "<li>x</li>".repeat(50_000);
    let page = article_page(&format!("<p>{LOREM}</p><p>{LOREM}</p><ul>{items}</ul>"));
    let a = extract(page.as_bytes()).unwrap();
    let nodes: usize = a
        .blocks
        .iter()
        .map(|b| match b {
            Block::List { items, .. } => 1 + items.len(),
            _ => 1,
        })
        .sum();
    assert!(nodes <= MAX_BLOCKS, "{nodes} nodes");
    assert!(a.truncated);
}

#[test]
fn r005_headings_and_metadata_are_inside_the_output_cap() {
    let huge = "h".repeat(600_000);
    let page = format!(
        "<html><head><title>{huge}</title></head><body><article><p>{LOREM}</p><p>{LOREM}</p><h2>{huge}</h2><h2>{huge}</h2></article></body></html>"
    );
    let a = match extract(page.as_bytes()) { Ok(a) => a, Err(e) => panic!("extract failed: {e:?}") };
    let total: usize = a.title.chars().count()
        + a.blocks
            .iter()
            .map(|b| match b {
                Block::Heading { text, .. }
                | Block::Para { text }
                | Block::Quote { text }
                | Block::Pre { text }
                | Block::Caption { text } => text.chars().count(),
                Block::List { items, .. } => items.iter().map(|i| i.chars().count()).sum(),
            })
            .sum::<usize>();
    assert!(total <= MAX_OUTPUT_CHARS, "{total} chars");
    assert!(a.truncated);
}

#[test]
fn r006_commented_out_meta_and_content_text_are_not_declarations() {
    let page = format!(
        "<!-- <meta charset=windows-1252> --><meta charset=utf-8><article><p>Caf\u{e9} {LOREM}</p><p>{LOREM}</p></article>"
    );
    assert!(texts(&extract(page.as_bytes()).unwrap()).contains("Caf\u{e9}"));
    let page = format!(
        "<meta name=\"description\" content=\"charset=shift_jis\"><article><p>{LOREM}</p><p>{LOREM}</p></article>"
    );
    assert!(extract(page.as_bytes()).is_ok());
}

#[test]
fn r007_undeclared_non_utf8_is_refused_not_guessed() {
    // windows-1251 bytes for a Russian word, no BOM and no meta declaration.
    let mut page = b"<article><p>".to_vec();
    page.extend_from_slice(LOREM.as_bytes());
    page.extend_from_slice(b" \xcf\xf0\xe8\xe2\xe5\xf2</p><p>");
    page.extend_from_slice(LOREM.as_bytes());
    page.extend_from_slice(b"</p></article>");
    assert!(matches!(extract(&page), Err(ReaderError::UnsupportedEncoding(_))));
}

#[test]
fn r008_inline_depth_truncation_is_reported() {
    let deep = format!("{}deep words{}", "<span>".repeat(130), "</span>".repeat(130));
    let page = article_page(&format!("<p>{LOREM}</p><p>{LOREM}</p><p>{deep}</p>"));
    let a = extract(page.as_bytes()).unwrap();
    assert!(texts(&a).contains("deep words") || a.truncated, "text dropped silently");
}

#[test]
fn r010_block_boundaries_inside_a_quote_survive() {
    let page = article_page(&format!(
        "<p>{LOREM}</p><blockquote><p>First paragraph.</p><p>Second paragraph.</p></blockquote><p>{LOREM}</p>"
    ));
    let t = texts(&extract(page.as_bytes()).unwrap());
    assert!(!t.contains("First paragraph.Second"), "{t}");
}

// The About row says Reader View shows the article "without the menus, ads
// and pop-ups around it". Each of those is checked here, not assumed.
#[test]
fn ads_sponsor_blocks_dialogs_cookie_banners_and_iframes_are_removed() {
    let page = article_page(&format!(
        "<p>{LOREM}</p>\
         <div class=\"advert-slot\"><p>Buy now, limited offer, while stocks last today.</p></div>\
         <div id=\"sponsor-box\"><p>Sponsored by somebody, with commas, and more.</p></div>\
         <iframe src=\"https://ads.example/frame\"></iframe>\
         <dialog open><p>Sign up for our newsletter, today, right now.</p></dialog>\
         <div role=\"dialog\"><p>Allow notifications, please, it is great.</p></div>\
         <div class=\"cookie-consent\"><p>We use cookies, as everyone does, to track.</p></div>\
         <p>{LOREM}</p>"
    ));
    let t = texts(&extract(page.as_bytes()).unwrap());
    for gone in ["Buy now", "Sponsored by", "ads.example", "newsletter", "notifications", "We use cookies"] {
        assert!(!t.contains(gone), "{gone} leaked into Reader View: {t}");
    }
}

// ---- review round 2 2026-10-07 (R-001), reproduced before fixing ----
// Each of these got past the old pre-scan, which modelled the parser's
// stack and got it wrong; the guard now reads the depth the parser builds.

#[test]
fn r2_001_a_self_closed_svg_does_not_hide_what_follows() {
    let page = format!(
        "<article><p>{LOREM}</p><svg/>{}<p>{LOREM}</p></article>",
        "<div>".repeat(100_000)
    );
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
}

#[test]
fn r2_001_an_end_tag_across_a_scope_boundary_does_not_reduce_nesting() {
    // </div> cannot close a div across <object>, so the parser keeps nesting.
    let page = format!(
        "<article><p>{LOREM}</p>{}<p>{LOREM}</p></article>",
        "<div><object></div>".repeat(20_000)
    );
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
}

#[test]
fn r2_001_reconstructed_formatting_elements_count_as_nesting() {
    // Each <b> start tag reopens every earlier <b> that </p> closed, so one
    // more level per round, from markup that never nests on its face.
    let mut page = format!("<article><p>{LOREM}</p>");
    for i in 0..5_000 {
        page.push_str(&format!("<p><b id=b{i}></p>"));
    }
    page.push_str("</article>");
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
}

#[test]
fn r2_001_nested_templates_count_as_nesting() {
    let page = format!(
        "<article><p>{LOREM}</p>{}</article>",
        "<template>".repeat(20_000)
    );
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
}

// ---- review round 3 2026-10-07 (R-001), reproduced before fixing ----

#[test]
fn r3_001_reopened_formatting_cannot_multiply_elements_below_the_depth_limit() {
    // 400 open <b>s closed by </p> stay "active": every later paragraph
    // reopens all 400, so under 1 MB of input asks for 40 million elements
    // while the tree never gets deeper than about 400.
    let mut page = String::from("<article><p>");
    for i in 0..400 {
        page.push_str(&format!("<b id=b{i}>"));
    }
    page.push_str("</p>");
    page.push_str(&"<p>x</p>".repeat(100_000));
    page.push_str("</article>");
    let t = std::time::Instant::now();
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
    assert!(t.elapsed() < std::time::Duration::from_secs(20), "took {:?}", t.elapsed());
}

// ---- review round 4 2026-10-07 (R-001, R-002), reproduced before fixing ----

#[test]
fn r4_001_reopened_attributes_count_against_the_budget() {
    // One <b> with 10,000 attributes, reopened in 10,000 paragraphs: few
    // elements, a hundred million attribute copies.
    let attrs: String = (0..10_000).map(|i| format!(" a{i}")).collect();
    let mut page = format!("<article><p><b{attrs}></p>");
    page.push_str(&"<p>x</p>".repeat(10_000));
    page.push_str("</article>");
    let t = std::time::Instant::now();
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
    assert!(t.elapsed() < std::time::Duration::from_secs(20), "took {:?}", t.elapsed());
}

#[test]
fn r4_002_one_tag_with_a_huge_number_of_attributes_is_cut_off_in_time() {
    // The tokenizer compares each new attribute with every earlier one in
    // the same tag, before any element exists for the budget to count.
    let attrs: String = (0..200_000).map(|i| format!(" a{i}")).collect();
    let page = format!("<article><p>text</p><div{attrs}>x</div></article>");
    let t = std::time::Instant::now();
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
    assert!(t.elapsed() < std::time::Duration::from_secs(20), "took {:?}", t.elapsed());
}

// ---- final review 2026-10-07 (R-001), reproduced before fixing ----

#[test]
fn final_001_a_long_attribute_reopened_many_times_is_refused() {
    // One <b> with a 1 MiB attribute, reopened in 100,000 paragraphs: few
    // elements and attributes, but 100 GiB of attribute text for the
    // cleaning pass to read.
    let big = "a".repeat(1 << 20);
    let mut page = format!("<article><p><b style=\"{big}\"></p>");
    page.push_str(&"<p>x</p>".repeat(100_000));
    page.push_str("</article>");
    let t = std::time::Instant::now();
    assert_eq!(extract(page.as_bytes()), Err(ReaderError::TooComplex));
    assert!(t.elapsed() < std::time::Duration::from_secs(20), "took {:?}", t.elapsed());
}
