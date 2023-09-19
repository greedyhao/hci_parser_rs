use hci_parser_rs::hci;
use hci_parser_rs::HciPacket;
use hci_parser_rs::InnerStack;

fn main() {
    let mut args = InnerStack::new();
    let cmd = [0x03, 0x0c, 0x00];
    // let cmd = [0x01, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0xff];
    let res = hci::parse(HciPacket::Cmd, &cmd, &mut args);
    for node in res {
        println!("{}", node.to_json().0);
    }
    println!("{:?}\n", args);

    // let acl = [0x80, 0x20, 0x0a, 0x00, 0x06, 0x00, 0x01, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x02, 0x00];
    // let res = hci::parse(HciPacket::Acl, &acl, &mut args);

    // for node in res {
    //     println!("{}", node.to_json().0);
    // }
    // println!("{:?}\n", args);

    // sdp
    let acl = [
        0x80, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x02, 0x04, 0x00, 0x01, 0x00, 0x40,
        0x00,
    ];
    let res = hci::parse(HciPacket::Acl, &acl, &mut args);
    for node in res {
        println!("{}", node.to_json().0);
    }
    println!("{:?}\n", args);

    let acl = [
        0x80, 0x20, 0x10, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x03, 0x02, 0x08, 0x00, 0x69, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let res = hci::parse(HciPacket::Acl, &acl, &mut args);
    for node in res {
        println!("{}", node.to_json().0);
    }
    println!("{:?}\n", args);

    let acl = [
        0x80, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x04, 0x04, 0x08, 0x00, 0x69, 0x00, 0x00,
        0x00, 0x01, 0x02, 0xc0, 0x00,
    ];
    let res = hci::parse(HciPacket::Acl, &acl, &mut args);

    for node in res {
        println!("{}", node.to_json().0);
    }
    println!("{:?}\n", args);
}
