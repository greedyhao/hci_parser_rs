pub mod hci;
pub use hci::HciPacket;

mod l2cap;
mod sdp;

use l2cap::L2CAPArg;
use sdp::SDPArg;

#[allow(unused)]
#[derive(Debug)]
pub struct HostStack {
    l2cap_arg: L2CAPArg,
    sdp_arg: SDPArg,
}

impl HostStack {
    pub fn new() -> Self {
        HostStack {
            l2cap_arg: L2CAPArg::default(),
            sdp_arg: SDPArg::default(),
        }
    }
}

pub trait ParseNode {
    fn new(data: &[u8], args: Option<&mut HostStack>) -> Self;
    fn as_json(&self, start_byte: u8) -> String;
}

pub trait ParseNodeA<T> {
    fn new(data: &[u8], args: Option<&mut HostStack>, param: T) -> Self;
    fn as_json(&self, start_byte: u8) -> String;
}

pub trait ParseNodeOpt: Sized {
    fn new(data: &[u8], args: Option<&mut HostStack>) -> Option<Self>;
    fn as_json(&self, start_byte: u8) -> String;
}

pub trait ParseNodeOptA<T>: Sized {
    fn new(data: &[u8], args: Option<&mut HostStack>, param: T) -> Option<Self>;
    fn as_json(&self, start_byte: u8) -> String;
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

pub struct ParseBytesNode {
    start_byte: u8,
    len_in_bytes: u8,
}

impl ParseBytesNode {
    fn new(start_byte: u8, len_in_bytes: u8) -> Self {
        ParseBytesNode {
            start_byte,
            len_in_bytes,
        }
    }

    fn format<T: ParseNodeFormat>(&self, key: &str, value: T, alias: &str, error: &str) -> String {
        format!(
            r#""{}": [{}, "{}", "B({}, {})", "{}"]"#,
            key,
            value.node_format(),
            alias,
            self.start_byte,
            self.len_in_bytes,
            error
        )
    }
}

pub struct ParseBitsNode {
    start_byte: u8,
    len_in_bytes: u8,
    start_bit: u8,
    len_in_bits: u8,
}

impl ParseBitsNode {
    fn new(start_byte: u8, len_in_bytes: u8, start_bit: u8, len_in_bits: u8) -> Self {
        ParseBitsNode {
            start_byte,
            len_in_bytes,
            start_bit,
            len_in_bits,
        }
    }

    fn format<T: ParseNodeFormat>(&self, key: &str, value: T, alias: &str, error: &str) -> String {
        format!(
            r#""{}": [{}, "{}", "B({}, {}), b({}, {})", "{}"]"#,
            key,
            value.node_format(),
            alias,
            self.start_byte,
            self.len_in_bytes,
            self.start_bit,
            self.len_in_bits,
            error
        )
    }
}

pub fn str_to_array(s: &str) -> Vec<u8> {
    s.split(' ')
        .map(|x| u8::from_str_radix(x, 16).unwrap())
        .collect()
}
