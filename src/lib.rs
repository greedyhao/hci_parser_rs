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

#[cfg(test)]
mod tests {
    #[test]
    fn hci_cmd_ogf3_reset_test() {
        use crate::hci;
        use crate::HciPacket::*;
        use crate::InnerStack;

        let mut args = InnerStack::new();
        let cmd = [0x03, 0x0c, 0x00];
        let res = hci::parse(Cmd, &cmd, &mut args);

        let res = res[0].to_json();
        assert_eq!(
            res.0,
            r#"{"Opcode":"0xc03", "OCF":"0x3", "OGF":"0x3", "Command":"Reset", "Parameter_Total_Length":"0x0"}"#
        );
        assert_eq!(
            res.1,
            r#"{"Opcode":"(0,2)", "OCF":"(0,1)", "OGF","(1,1)", "Command":"(0,2)", "Parameter_Total_Length":"(2,1),0"}"#
        );
    }
}
