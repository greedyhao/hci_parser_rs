pub mod hci;
pub use hci::HciPacket;
pub mod l2cap;

use l2cap::L2capArg;

#[derive(Debug)]
pub struct HostStack {
    l2cap_arg: L2capArg,
}

impl HostStack {
    pub fn new() -> Self {
        HostStack {
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

impl ParseStatus {
    fn get_value(&self) -> u8 {
        match self {
            ParseStatus::Ok => 0,
            ParseStatus::SubtreeStart => 1,
            ParseStatus::SubtreeEnd => 2,
            ParseStatus::Error => 3,
        }
    }
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
    fn new<T: ParseNodeFormat>(
        key: &str,
        value: T,
        option: Option<&str>,
        length: u8,
        status: ParseStatus,
    ) -> Self {
        let value = if option.is_some() {
            let option = option.unwrap();
            format!(r#""{}({option})""#, value.node_format())
        } else {
            format!("{}", value.node_format())
        };
        ParseNodeSubInfo {
            key: key.to_string(),
            value,
            length,
            status,
        }
    }

    fn append_major_info(&self, major: &mut String, without_separator: bool) {
        if !without_separator {
            major.push_str(&format!(r#", "{}": {}"#, self.key, self.value));
        } else {
            major.push_str(&format!(r#""{}": {}"#, self.key, self.value));
        }
    }

    fn append_minor_info(&self, minor: &mut String, without_separator: bool, index: u8) {
        if !without_separator {
            minor.push_str(&format!(
                r#", "{}": "({},{})""#,
                self.key, index, self.length
            ));
        } else {
            minor.push_str(&format!(r#""{}": "({},{})""#, self.key, index, self.length));
        }
        if self.status != ParseStatus::Ok {
            minor.push_str(format!(r#",{}"#, self.status.get_value()).as_str());
        }
    }
}

pub struct ParseNodeInfo {
    name: String,
    sub_info: Vec<ParseNodeSubInfo>,
}

impl ParseNodeInfo {
    fn new(name: &str, sub_info: Vec<ParseNodeSubInfo>) -> Self {
        ParseNodeInfo {
            name: name.to_string(),
            sub_info,
        }
    }
}

use duplicate::duplicate_item;

pub trait ParseNodeFormat {
    fn node_format(&self) -> String;
}

#[duplicate_item(
    int_type;
    [ u8 ]; [ &u8 ];
    [ u16 ]; [ &u16 ];
    [ u32 ]; [ &u32 ];
)]
impl ParseNodeFormat for int_type {
    fn node_format(&self) -> String {
        format!("{:#x}", self)
    }
}

#[duplicate_item(
    str_type;
    [ &str ];
    [ String ];
)]
impl ParseNodeFormat for str_type {
    fn node_format(&self) -> String {
        format!(r#""{}""#, self)
    }
}

pub fn format_parse_node<T: ParseNodeFormat>(key: &str, value: T, option: Option<&str>) -> String {
    let value = if option.is_some() {
        let option = option.unwrap();
        format!(r#""{}({option})""#, value.node_format())
    } else {
        format!("{}", value.node_format())
    };

    format!(r#""{}": {}"#, key, value)
}
