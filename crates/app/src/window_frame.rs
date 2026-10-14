//! The window controls PATANYX draws on Windows, where the window has no
//! title bar (1.0.7): its height goes to the page, and the brand mark in the
//! toolbar already names the browser.
//!
//! On Windows the main window is built undecorated with tao's undecorated
//! shadow (main.rs). tao then removes WS_CAPTION only, so the window keeps its
//! resize, minimize, maximize and system-menu styles (Win+arrow snapping,
//! Alt+Space), its shadow, and invisible resize borders on the left, right and
//! bottom. The top edge and everything a title bar did are the chrome's: it
//! draws Minimize, Maximize/Restore and Close at the right end of the tab
//! strip, lends the strip's empty space as the drag area, and keeps a thin
//! resize band along the top. Each of those sends one `window_control`
//! command, parsed HERE, so a misspelled or unknown action is refused rather
//! than guessed at. Linux keeps its desktop's title bar and never sends any.
//!
//! What is lost, and said so in the tester notes: the Snap Layouts flyout on
//! hovering Maximize (it needs a non-client HTMAXBUTTON hit test), and the
//! right-click window menu on the bar (Alt+Space still opens it).

use serde_json::Value;

/// The edge a top resize band starts a resize from. Only the top: the other
/// three edges keep the system's own resize borders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizeEdge {
    North,
    NorthWest,
    NorthEast,
}

/// One title-bar action from the chrome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowAction {
    Minimize,
    /// Maximize, or restore when already maximized.
    Maximize,
    Close,
    /// Start the system's move loop (Aero Snap included) from a press.
    Drag,
    /// Start the system's resize loop from a press on the top band.
    Resize(ResizeEdge),
}

impl WindowAction {
    /// `{action}` plus, for a resize, `{edge}`. Anything else is refused.
    pub fn from_args(args: &Value) -> Option<Self> {
        let action = args.get("action")?.as_str()?;
        Some(match action {
            "minimize" => Self::Minimize,
            "maximize" => Self::Maximize,
            "close" => Self::Close,
            "drag" => Self::Drag,
            "resize" => Self::Resize(match args.get("edge")?.as_str()? {
                "n" => ResizeEdge::North,
                "nw" => ResizeEdge::NorthWest,
                "ne" => ResizeEdge::NorthEast,
                _ => return None,
            }),
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn each_action_parses_to_itself() {
        for (args, want) in [
            (json!({ "action": "minimize" }), WindowAction::Minimize),
            (json!({ "action": "maximize" }), WindowAction::Maximize),
            (json!({ "action": "close" }), WindowAction::Close),
            (json!({ "action": "drag" }), WindowAction::Drag),
            (json!({ "action": "resize", "edge": "n" }), WindowAction::Resize(ResizeEdge::North)),
            (json!({ "action": "resize", "edge": "nw" }), WindowAction::Resize(ResizeEdge::NorthWest)),
            (json!({ "action": "resize", "edge": "ne" }), WindowAction::Resize(ResizeEdge::NorthEast)),
        ] {
            assert_eq!(WindowAction::from_args(&args), Some(want), "{args}");
        }
    }

    #[test]
    fn anything_else_is_refused() {
        for args in [
            json!({}),
            json!({ "action": "" }),
            json!({ "action": "Minimize" }),
            json!({ "action": "fullscreen" }),
            json!({ "action": 1 }),
            json!({ "action": "resize" }),
            json!({ "action": "resize", "edge": "s" }),
            json!({ "action": "resize", "edge": "w" }),
            json!({ "action": "resize", "edge": 2 }),
        ] {
            assert_eq!(WindowAction::from_args(&args), None, "{args}");
        }
    }
}
