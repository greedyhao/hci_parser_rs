pub mod hci;
pub use hci::HciPacket;
pub mod l2cap;

use l2cap::L2capArg;

#[derive(Debug)]
pub struct InnerStack {
    l2cap_arg: L2capArg,
}

impl InnerStack {
    pub fn new() -> Self {
        InnerStack {
            l2cap_arg: L2capArg::default(),
        }
    }
}

#[derive(PartialEq)]
pub enum ParseStatus {
    Ok = 0,
    SubtreeStart,
    SubtreeEnd,
    Error,
}

pub trait ParseLayer {
    /// json format (major, minor)
    ///
    /// + major: Depending on the layer
    /// + minor: (start index, length(bytes)), status(optional)
    ///
    /// ParseLayer::to_json always depend on ParseNode::get_info
    fn to_json(&self) -> (String, String);
}

/// Subset of the `ParseLayer`
pub trait ParseNode {
    fn new(data: &[u8]) -> Self;
    fn get_info(&self) -> ParseNodeInfo;
}

pub struct ParseNodeSubInfo {
    key: String,
    value: String,
    length: u8,
    status: ParseStatus,
}

impl ParseNodeSubInfo {
    fn new(key: String, value: String, length: u8, status: ParseStatus) -> Self {
        ParseNodeSubInfo {
            key,
            value,
            length,
            status,
        }
    }
}

pub struct ParseNodeInfo {
    name: String,
    sub_info: Vec<ParseNodeSubInfo>,
}

impl ParseNodeInfo {
    fn new(name: String, sub_info: Vec<ParseNodeSubInfo>) -> Self {
        ParseNodeInfo { name, sub_info }
    }
}
