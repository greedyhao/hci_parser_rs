use hci_parser_rs::hci;
use hci_parser_rs::HciPacket;
use hci_parser_rs::HostStack;

fn str_to_array(s: &str) -> Vec<u8> {
    s.split(' ').map(|x| u8::from_str_radix(x, 16).unwrap()).collect()
}

fn main() {
    let mut args = HostStack::new();
    let cmd = [0x03, 0x0c, 0x00];
    // let cmd = [0x01, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0xff];
    let res = hci::parse(HciPacket::Cmd, &cmd, &mut args);
    for node in res {
        println!("{}", node.to_json().0);
        println!("{}", node.to_json().1);
    }
    println!("{:?}\n", args);

    // let acl = [0x80, 0x20, 0x0a, 0x00, 0x06, 0x00, 0x01, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x02, 0x00];
    // let res = hci::parse(HciPacket::Acl, &acl, &mut args);

    // for node in res {
    //     println!("{}", node.to_json().0);
    // }
    // println!("{:?}\n", args);

    // sdp
    let acl = str_to_array("80 00 0c 00 08 00 01 00 02 02 04 00 01 00 40 00");
    let res = hci::parse(HciPacket::Acl, &acl, &mut args);
    for node in res {
        println!("{}", node.to_json().0);
    }
    println!("--- {:?}\n", args);

    let acl = str_to_array("80 20 10 00 0c 00 01 00 03 02 08 00 69 00 40 00 00 00 00 00");
    let res = hci::parse(HciPacket::Acl, &acl, &mut args);
    for node in res {
        println!("{}", node.to_json().0);
    }
    println!("--- {:?}\n", args);

    let acl = str_to_array("80 00 10 00 0c 00 01 00 04 04 08 00 69 00 00 00 01 02 c0 00");
    let res = hci::parse(HciPacket::Acl, &acl, &mut args);
    for node in res {
        println!("{}", node.to_json().0);
    }
    println!("--- {:?}\n", args);

    let acl = str_to_array("80 20 10 00 0c 00 01 00 04 05 08 00 40 00 00 00 01 02 00 04");
    let res = hci::parse(HciPacket::Acl, &acl, &mut args);
    for node in res {
        println!("{}", node.to_json().0);
    }
    println!("--- {:?}\n", args);

    let acl = str_to_array("80 00 12 00 0e 00 01 00 05 05 0a 00 69 00 00 00 00 00 01 02 c0 00");
    let res = hci::parse(HciPacket::Acl, &acl, &mut args);
    for node in res {
        println!("{}", node.to_json().0);
    }
    println!("--- {:?}\n", args);
}
