use hci_parser_rs::HciPacket;
use hci_parser_rs::InnerStack;
use hci_parser_rs::hci;

fn main() {
    let mut args = InnerStack {};
    // let cmd = [0x03, 0x0c, 0x00];
    // let cmd = [0x01, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0xff];
    // let res = hci::parse(HciPacket::Cmd, &cmd, &mut args);
    
    let acl = [0x80, 0x20, 0x0a, 0x00, 0x06, 0x00, 0x01, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x02, 0x00];
    let res = hci::parse(HciPacket::Acl, &acl, &mut args);

    for node in res {
        println!("{}", node.to_json().0);
    }
}
