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
    LinkControl = 0x01,
    LinkPolicy,
    ControlAndBaseBand,
    InformationalParameters,
    StatusParameters,
    Testing,
    LeController = 0x08,
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

        let info = self.param.get_info();
        let mut main = format!(
            r#"{{"Opcode":"{:#x}", "OCF":"{:#x}", "OGF":"{:#x}", "Command":"{}", "Parameter_Total_Length":"{:#x}""#,
            self.opcode, ocf, ogf, info.0, self.param_total_len
        );
        let mut index = format!(
            r#"{{"Opcode":"0,2", "OCF":"0,1", "OGF","1,1", "Command":"0,2", "Parameter_Total_Length":"2,1,0""#
        );

        let mut cnt = 3;
        for sub in info.1 {
            main.push_str(format!(r#", {}:{}"#, sub.0, sub.1).as_str());
            index.push_str(format!(r#", "{}":"{},{}""#, sub.0, cnt, sub.2).as_str());
            cnt += sub.2;
        }
        main.push_str("}");
        index.push_str("}");
        (main, index)
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

pub fn parse(
    packet_type: HciPacket,
    data: &[u8],
    _args: &mut InnerStack,
) -> Vec<Box<dyn ParseLayer>> {
    let node: Box<dyn ParseLayer> = match packet_type {
        HciPacket::Cmd => {
            if data.len() < 3 {
                println!("data size err!(less than 3B)");
            }

            let opcode = data[0] as u16 | (data[1] as u16) << 8;
            let ocf = opcode & 0x3FF;
            let ogf = opcode >> 10;

            let ogf_conv: HciCmdOgf = unsafe { std::mem::transmute(ogf as u8) };

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

            ret
        }
        _ => {
            let cmd: HciCmd<HciParseDummy> = HciCmd::new(data);
            Box::new(cmd)
        }
    };
    vec![node]
}
