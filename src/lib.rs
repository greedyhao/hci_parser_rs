pub mod hci;
pub use hci::HciPacket;
pub mod l2cap;

pub struct InnerStack {}

#[derive(PartialEq)]
pub enum ParseStatus {
    Ok = 0,
    Error
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
    fn get_info(&self) -> (String, Vec<(String, String, u8, ParseStatus)>);
}
