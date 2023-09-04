use std::vec;

use crate::l2cap;
use crate::InnerStack;
use crate::ParseLayer;
use crate::ParseNode;
use crate::ParseStatus;

#[allow(unused)]
pub enum HciPacket {
    Cmd,
    Acl,
    Sco,
    Evt,
    Iso,
}

#[allow(unused)]
#[repr(u8)]
enum HciCmdOgf {
    NoUse = 0,
    LinkControl = 0x01,
    LinkPolicy,
    ControlAndBaseBand,
    InformationalParameters,
    StatusParameters,
    Testing,
    LeController = 0x08,
}

impl HciCmdOgf {
    fn from_u8(ogf: u8) -> Self {
        use HciCmdOgf::*;
        match ogf {
            0x01 => LinkControl,
            0x02 => LinkPolicy,
            0x03 => ControlAndBaseBand,
            0x04 => InformationalParameters,
            0x05 => StatusParameters,
            0x06 => Testing,
            0x08 => LeController,
            _ => NoUse,
        }
    }
}

#[derive(Debug)]
struct HciCmd<T> {
    opcode: u16,
    param_total_len: u8,
    param: T,
}

impl<T: ParseNode> HciCmd<T> {
    fn new(data: &[u8]) -> Self {
        let opcode = data[0] as u16 | (data[1] as u16) << 8;
        let param_total_len = data[2];
        HciCmd {
            opcode,
            param_total_len,
            param: T::new(&data[3..]),
        }
    }
}

impl<T: ParseNode> ParseLayer for HciCmd<T> {
    fn to_json(&self) -> (String, String) {
        let ocf = self.opcode & 0x3FF;
        let ogf = self.opcode >> 10;

        let opcode_s = "Opcode";
        let ocf_s = "OCF";
        let ogf_s = "OGF";
        let command_s = "Command";
        let param_total_len_s = "Parameter_Total_Length";
        let info = self.param.get_info();
        let mut major = format!(
            r#"{{"{}":"{:#x}", "{}":"{:#x}", "{}":"{:#x}", "{}":"{}", "{}":"{:#x}""#,
            opcode_s,
            self.opcode,
            ocf_s,
            ocf,
            ogf_s,
            ogf,
            command_s,
            info.0,
            param_total_len_s,
            self.param_total_len
        );
        let mut minor = format!(
            r#"{{"{}":"(0,2)", "{}":"(0,1)", "{}","(1,1)", "{}":"(0,2)", "{}":"(2,1),0""#,
            opcode_s, ocf_s, ogf_s, command_s, param_total_len_s
        );

        let mut cnt = 3;
        for sub in info.1 {
            major.push_str(format!(r#", {}:{}"#, sub.0, sub.1).as_str());
            minor.push_str(format!(r#", "{}":"({},{})""#, sub.0, cnt, sub.2).as_str());
            if sub.3 != ParseStatus::Ok {
                minor.push_str(format!(r#",{}"#, sub.3 as u8).as_str());
            }
            cnt += sub.2;
        }
        major.push_str("}");
        minor.push_str("}");
        (major, minor)
    }
}

// Dummy
struct HciParseDummy {}

impl ParseNode for HciParseDummy {
    fn new(_data: &[u8]) -> Self {
        HciParseDummy {}
    }
    fn get_info(&self) -> (String, Vec<(String, String, u8, ParseStatus)>) {
        (String::from("Dummy"), vec![])
    }
}

// LinkControl
#[derive(Debug)]
enum HciCmdLinkControl {
    NoUse = 0,
    Inquiry = 1,
}

impl HciCmdLinkControl {
    fn from_u16(ocf: u16) -> Self {
        match ocf {
            1 => HciCmdLinkControl::Inquiry,
            _ => HciCmdLinkControl::NoUse,
        }
    }
}

#[derive(Debug)]
struct HciCmdOgf1Inquiry {
    lap: [u8; 3],
    inquiry_length: u8,
    num_responses: u8,
}

impl ParseNode for HciCmdOgf1Inquiry {
    fn new(data: &[u8]) -> Self {
        HciCmdOgf1Inquiry {
            lap: data[0..3].try_into().expect("slice with incorrect length"),
            inquiry_length: data[3],
            num_responses: data[4],
        }
    }
    fn get_info(&self) -> (String, Vec<(String, String, u8, ParseStatus)>) {
        let lap = (self.lap[0] as u32) | (self.lap[1] as u32) << 8 | (self.lap[2] as u32) << 16;
        let lap_check = if lap >= 0x9E8B00 && lap <= 0x9E8B3F {
            ParseStatus::Ok
        } else {
            ParseStatus::Error
        };

        let inquiry_length = self.inquiry_length;
        let inquiry_length_check = if inquiry_length >= 0x1 && inquiry_length <= 0x30 {
            ParseStatus::Ok
        } else {
            ParseStatus::Error
        };

        (
            String::from("Inquiry"),
            vec![
                (String::from("LAP"), format!("{:#x}", lap), 3, lap_check),
                (
                    String::from("Inquiry_Length"),
                    format!("{:#x}", self.inquiry_length),
                    1,
                    inquiry_length_check,
                ),
                (
                    String::from("Num_Responses"),
                    format!("{:#x}", self.num_responses),
                    1,
                    ParseStatus::Ok,
                ),
            ],
        )
    }
}

// LinkPolicy

// #[repr(u16)]
// enum HciCmdLinkPolicy {
//     NoUse = 0,
//     HoldMode = 1,
// }

// ControlAndBaseBand
#[repr(u16)]
enum HciCmdControlAndBaseband {
    NoUse = 0,
    // SetEventMask = 1,
    Reset = 3,
    // SetEventFilter = 5,
}

impl HciCmdControlAndBaseband {
    fn from_u16(ocf: u16) -> Self {
        match ocf {
            3 => HciCmdControlAndBaseband::Reset,
            _ => HciCmdControlAndBaseband::NoUse,
        }
    }
}

#[derive(Debug)]
struct HciCmdOgf3Reset {}

impl ParseNode for HciCmdOgf3Reset {
    fn new(_data: &[u8]) -> Self {
        HciCmdOgf3Reset {}
    }
    fn get_info(&self) -> (String, Vec<(String, String, u8, ParseStatus)>) {
        (String::from("Reset"), vec![])
    }
}

// InformationalParameters

// #[repr(u16)]
// enum HciCmdInformationalParameters {
//     NoUse = 0,
//     ReadLocalVersionInformation = 1,
// }

// StatusParameters

// #[repr(u16)]
// enum HciCmdStatusParameters {
//     NoUse = 0,
//     ReadFailedContactCounter = 1,
// }

// Testing

// #[repr(u16)]
// enum HciCmdTesting {
//     NoUse = 0,
//     ReadLoopbackMode = 1,
// }

// LeController

// #[repr(u16)]
// enum HciCmdLeController {
//     NoUse = 0,
//     LeSetEventMask = 1,
// }

/// HCI ACL

// struct HciAcl<T> {
//     /// Handle:[0-11], PB Flag:[12-13], PC Flag:[14-15]
//     handle_and_flags: u16,
//     data_total_length: u16,
//     data: T,
// }

// impl<T: ParseNode> HciAcl<T> {
//     fn new(data: &[u8]) -> Self {
//         let handle_and_flags = data[0] as u16 | (data[1] as u16) << 8;
//         let data_total_length = data[2] as u16 | (data[3] as u16) << 8;
//         HciAcl {
//             handle_and_flags,
//             data_total_length,
//             data: T::new(&data[4..]),
//         }
//     }
// }

// impl<T: ParseNode> ParseLayer for HciAcl<T> {
//     fn to_json(&self) -> (String, String) {
//         let handle_s = "Handle";
//         let pb_flag_s = "PB Flag";
//         let pc_flag_s = "PC Flag";
//         let data_total_length_s = "Data Total Length";

//         let mut major = format!(
//             r#"{{"{}":"{:#x}", "{}":"{:#x}", "{}":"{:#x}", "{}":"{:#x}""#,
//             handle_s,
//             self.handle_and_flags & 0xfff,
//             pb_flag_s,
//             (self.handle_and_flags >> 12) & 0x3,
//             pc_flag_s,
//             self.handle_and_flags >> 14,
//             data_total_length_s,
//             self.data_total_length
//         );
//         let mut minor = format!(
//             r#"{{"{}":"(0,2)", "{}":"(1,1)", "{}","(1,1)", "{}":"(2,2)""#,
//             handle_s, pb_flag_s, pc_flag_s, data_total_length_s
//         );

//         major.push_str("}");
//         minor.push_str("}");
//         (major, minor)
//     }
// }

pub fn parse(
    packet_type: HciPacket,
    data: &[u8],
    args: &mut InnerStack,
) -> Vec<Box<dyn ParseLayer>> {
    use HciPacket::*;
    let node: Vec<Box<dyn ParseLayer>> = match packet_type {
        Cmd => {
            if data.len() < 3 {
                println!("data size err!(less than 3B)");
            }

            let opcode = data[0] as u16 | (data[1] as u16) << 8;
            let ocf = opcode & 0x3FF;
            let ogf = opcode >> 10;

            let ogf_conv = HciCmdOgf::from_u8(ogf as u8);

            use HciCmdControlAndBaseband::*;
            use HciCmdLinkControl::*;
            use HciCmdOgf::*;

            let ret: Box<dyn ParseLayer> = match ogf_conv {
                LinkControl => {
                    let ocf_conv = HciCmdLinkControl::from_u16(ocf);
                    let ret: Box<dyn ParseLayer> = match ocf_conv {
                        Inquiry => {
                            let cmd: HciCmd<HciCmdOgf1Inquiry> = HciCmd::new(data);
                            Box::new(cmd)
                        }
                        _ => {
                            let cmd: HciCmd<HciParseDummy> = HciCmd::new(data);
                            Box::new(cmd)
                        }
                    };
                    ret
                }
                ControlAndBaseBand => {
                    let ocf_conv = HciCmdControlAndBaseband::from_u16(ocf);
                    let ret: Box<dyn ParseLayer> = match ocf_conv {
                        Reset => {
                            let cmd: HciCmd<HciCmdOgf3Reset> = HciCmd::new(data);
                            Box::new(cmd)
                        }
                        _ => {
                            let cmd: HciCmd<HciParseDummy> = HciCmd::new(data);
                            Box::new(cmd)
                        }
                    };
                    ret
                }
                _ => {
                    let cmd: HciCmd<HciParseDummy> = HciCmd::new(data);
                    Box::new(cmd)
                }
            };

            vec![ret]
        }
        Acl => {
            if data.len() < 4 {
                println!("data size err!(less than 4B)");
            }
            let ret = l2cap::parse(data, args);
            ret
        }
        _ => {
            let cmd: HciCmd<HciParseDummy> = HciCmd::new(data);
            vec![Box::new(cmd)]
        }
    };
    node
}
