
mod hci;
use hci::HciPacket;

pub struct InnerStack {}

pub enum ParseStatus {
    Ok = 0,
    Error
}

pub trait ParseLayer {
    /// json format
    /// (major, minor)
    /// major: Depending on the layer
    /// minor: start index, length, status(optional)
    /// 
    /// ParseLayer::to_json always depend on ParseNode::get_info
    fn to_json(&self) -> (String, String);
}

pub trait ParseNode {
    fn new(data: &[u8]) -> Self;
    fn get_info(&self) -> (String, Vec<(String, String, u8, ParseStatus)>);
}

fn main() {
    let mut args = InnerStack {};
    let cmd = [0x03, 0x0c, 0x00];
    // let cmd = [0x01, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0xff];
    let res = hci::parse(HciPacket::Cmd, &cmd, &mut args);

    for node in res {
        println!("{}", node.to_json().0);
    }
}
