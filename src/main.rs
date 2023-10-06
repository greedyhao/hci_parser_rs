use hci_parser_rs::hci;
// use hci_parser_rs::HciPacket;
use hci_parser_rs::HostStack;

use hci_parser_rs::str_to_array;

fn main() {
    let mut args = HostStack::new();

    // reset
    let cmd = str_to_array("01 03 0c 00");
    let res = hci::parse(&cmd, &mut args);
    println!("res:{}\nargs:{:?}\n", res, args);
    let evt = str_to_array("04 0e 04 05 03 0c 00");
    let res = hci::parse(&evt, &mut args);
    println!("res:{}\nargs:{:?}\n", res, args);

    // inquiry
    let cmd = str_to_array("01 01 04 05 01 02 03 04 ff");
    let res = hci::parse(&cmd, &mut args);
    println!("res:{}\nargs:{:?}\n", res, args);

    // sdp
    let acl = str_to_array("02 80 00 0c 00 08 00 01 00 02 02 04 00 01 00 40 00");
    let res = hci::parse(&acl, &mut args);
    println!("res:{}\nargs:{:?}\n", res, args);

    let acl = str_to_array("02 80 20 10 00 0c 00 01 00 03 02 08 00 69 00 40 00 00 00 00 00");
    let res = hci::parse(&acl, &mut args);
    println!("res:{}\nargs:{:?}\n", res, args);

    let acl = str_to_array("02 80 00 10 00 0c 00 01 00 04 04 08 00 69 00 00 00 01 02 c0 00");
    let res = hci::parse(&acl, &mut args);
    println!("res:{}\nargs:{:?}\n", res, args);

    let acl = str_to_array("02 80 20 10 00 0c 00 01 00 04 05 08 00 40 00 00 00 01 02 00 04");
    let res = hci::parse(&acl, &mut args);
    println!("res:{}\nargs:{:?}\n", res, args);

    let acl = str_to_array("02 80 00 12 00 0e 00 01 00 05 05 0a 00 69 00 00 00 00 00 01 02 c0 00");
    let res = hci::parse(&acl, &mut args);
    println!("res:{}\nargs:{:?}\n", res, args);

    let acl = str_to_array("02 80 20 0e 00 0a 00 01 00 05 04 06 00 40 00 00 00 00 00");
    let res = hci::parse(&acl, &mut args);
    println!("res:{}\nargs:{:?}\n", res, args);

    // let acl = str_to_array("02 80 00 16 00 12 00 69 00 06 00 01 00 0d 35 03 19 11 0a 00 c0 35 03 09 00 04 00");
}
