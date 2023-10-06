use crate::l2cap::L2cap;
use crate::HostStack;
use crate::ParseNode;
use crate::ParseNodeWithArgs;

use crate::ParseBitsNode;
use crate::ParseBytesNode;

#[derive(Debug)]
pub enum HciPacket {
    Undefined,
    Cmd(HciCmd),
    Acl(HciAcl),
    Sco,
    Evt(HciEvt),
    Iso,
}

impl ParseNodeWithArgs for HciPacket {
    fn new(data: &[u8], args: &mut HostStack) -> Self {
        let packet_type = data[0];
        let data = &data[1..];
        match packet_type {
            1 => HciPacket::Cmd(HciCmd::new(data)),
            2 => HciPacket::Acl(HciAcl::new(data, args)),
            3 => HciPacket::Sco,
            4 => HciPacket::Evt(HciEvt::new(data)),
            5 => HciPacket::Iso,
            _ => HciPacket::Undefined,
        }
    }

    fn as_json(&self, start_byte: u8) -> String {
        let start_byte = start_byte + 1;
        match self {
            HciPacket::Cmd(pkg) => pkg.as_json(start_byte),
            HciPacket::Acl(pkg) => pkg.as_json(start_byte),
            HciPacket::Evt(pkg) => pkg.as_json(start_byte),
            _ => "".to_string(),
        }
    }
}

trait HciCmdOgfNode {
    fn new(data: &[u8], opcode: u16) -> Self;
    fn as_json(&self, start_byte: u8) -> String;
}

#[derive(Debug)]
pub struct HciCmd {
    opcode: u16,
    param_len: u8,
    param: HciCmdParam,
}

impl HciCmd {
    fn fake_new(opcode: u16) -> Self {
        let mut data = vec![0; 255];
        data[0] = (opcode & 0xff) as u8;
        data[1] = ((opcode >> 8) & 0xff) as u8;
        let param_len = data[2];
        let param = HciCmdParam::new(&data, opcode);
        HciCmd {
            opcode,
            param_len,
            param,
        }
    }
}

impl ParseNode for HciCmd {
    fn new(data: &[u8]) -> Self {
        let opcode = u16::from_le_bytes([data[0], data[1]]);
        let param_len = data[2];
        let param = HciCmdParam::new(data, opcode);
        HciCmd {
            opcode,
            param_len,
            param,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let ocf = opcode_to_ogf(self.opcode);
        let ogf = opcode_to_ocf(self.opcode);
        let ocf_s = ParseBitsNode::new(start_byte, 2, 0, 10).format(
            "Opcode Command Field (OCF)",
            ocf,
            self.param.get_ocf_name(),
            "",
        );
        let ogf_s = ParseBitsNode::new(start_byte + 1, 1, 10, 6).format(
            "Opcode Group Field (OGF)",
            ogf,
            self.param.get_ogf_name(),
            "",
        );
        let param_len_s = ParseBytesNode::new(start_byte + 2, 1).format(
            "Parameter Total Length",
            self.param_len,
            "",
            "",
        );
        format!(r#""Opcode": {{{}, {}}}, {}"#, ogf_s, ocf_s, param_len_s)
    }
}

#[derive(Debug)]
enum HciCmdParam {
    Undefined,
    LinkControl(OgfLinkControl),
    LinkPolicy,
    ControllerAndBaseband(OgfControllerAndBaseband),
    InformationalParameters,
    StatusParameters,
    Testing,
    LeController,
}

impl HciCmdParam {
    fn get_ogf_name(&self) -> &'static str {
        match self {
            HciCmdParam::LinkControl(_) => "Link Control",
            HciCmdParam::LinkPolicy => "Link Policy",
            HciCmdParam::ControllerAndBaseband(_) => "Controller & Baseband",
            HciCmdParam::InformationalParameters => "Informational Parameters",
            HciCmdParam::StatusParameters => "Status Parameters",
            HciCmdParam::Testing => "Testing",
            HciCmdParam::LeController => "LE Controller",
            HciCmdParam::Undefined => "Undefined",
        }
    }

    fn get_ocf_name(&self) -> &'static str {
        match self {
            HciCmdParam::LinkControl(cmd) => cmd.get_ocf_name(),
            HciCmdParam::ControllerAndBaseband(cmd) => cmd.get_ocf_name(),
            _ => "",
        }
    }
}

impl HciCmdOgfNode for HciCmdParam {
    fn new(data: &[u8], opcode: u16) -> Self {
        let ogf = opcode_to_ogf(opcode);
        match ogf {
            1 => HciCmdParam::LinkControl(OgfLinkControl::new(data, opcode)),
            2 => HciCmdParam::LinkPolicy,
            3 => HciCmdParam::ControllerAndBaseband(OgfControllerAndBaseband::new(data, opcode)),
            4 => HciCmdParam::InformationalParameters,
            5 => HciCmdParam::StatusParameters,
            6 => HciCmdParam::Testing,
            8 => HciCmdParam::LeController,
            _ => HciCmdParam::Undefined,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let body = match self {
            HciCmdParam::LinkControl(cmd) => cmd.as_json(start_byte),
            HciCmdParam::LinkPolicy => "".to_string(),
            HciCmdParam::ControllerAndBaseband(cmd) => cmd.as_json(start_byte),
            HciCmdParam::InformationalParameters => "".to_string(),
            HciCmdParam::StatusParameters => "".to_string(),
            HciCmdParam::Testing => "".to_string(),
            HciCmdParam::LeController => "".to_string(),
            HciCmdParam::Undefined => "".to_string(),
        };
        format!(r#""HCI": {{{}}}"#, body)
    }
}

#[derive(Debug)]
enum OgfLinkControl {
    Undefined,
    Inquiry(OcfInquiry),
}

impl OgfLinkControl {
    fn get_ocf_name(&self) -> &'static str {
        match self {
            OgfLinkControl::Inquiry(_) => "Inquiry",
            _ => "",
        }
    }
}
impl HciCmdOgfNode for OgfLinkControl {
    fn new(data: &[u8], opcode: u16) -> Self {
        let ocf = opcode_to_ogf(opcode);
        match ocf {
            1 => OgfLinkControl::Inquiry(OcfInquiry::new(data)),
            _ => OgfLinkControl::Undefined,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        match self {
            OgfLinkControl::Inquiry(cmd) => cmd.as_json(start_byte),
            _ => "".to_string(),
        }
    }
}

#[derive(Debug)]
struct OcfInquiry {
    lap: u32,
    inquiry_len: u8,
    num_resp: u8,
}

impl ParseNode for OcfInquiry {
    fn new(data: &[u8]) -> Self {
        let lap = data[0] as u32 | (data[1] as u32) << 8 | (data[2] as u32) << 16;
        let inquiry_len = data[3];
        let num_resp = data[4];
        OcfInquiry {
            lap,
            inquiry_len,
            num_resp,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let lap_s = ParseBytesNode::new(start_byte, 3).format("LAP", self.lap, "", "");
        let inquiry_len_s = ParseBytesNode::new(start_byte + 3, 1).format(
            "Inquiry Length",
            self.inquiry_len,
            "",
            "",
        );
        let num_resp_s = ParseBytesNode::new(start_byte + 4, 1).format(
            "Number of Responses",
            self.num_resp,
            "",
            "",
        );
        format!(r#"{}, {}, {}"#, lap_s, inquiry_len_s, num_resp_s)
    }
}

#[derive(Debug)]
enum OgfControllerAndBaseband {
    Undefined,
    Reset(OcfReset),
}

impl OgfControllerAndBaseband {
    fn get_ocf_name(&self) -> &'static str {
        match self {
            OgfControllerAndBaseband::Reset(_) => "Reset",
            _ => "",
        }
    }
}

impl HciCmdOgfNode for OgfControllerAndBaseband {
    fn new(data: &[u8], opcode: u16) -> Self {
        let ocf = opcode_to_ogf(opcode);
        match ocf {
            3 => OgfControllerAndBaseband::Reset(OcfReset::new(data)),
            _ => OgfControllerAndBaseband::Undefined,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        match self {
            OgfControllerAndBaseband::Reset(reset) => reset.as_json(start_byte),
            _ => "".to_string(),
        }
    }
}

#[derive(Debug)]
struct OcfReset {}

impl ParseNode for OcfReset {
    fn new(_data: &[u8]) -> Self {
        OcfReset {}
    }
    fn as_json(&self, start_byte: u8) -> String {
        ParseBytesNode::new(start_byte, 0).format("Reset", "", "", "")
    }
}

#[derive(Debug)]
pub struct HciAcl {
    handle: u16,
    pb_flag: u8,
    bc_flag: u8,
    data_len: u16,
    data: L2cap,
}

impl ParseNodeWithArgs for HciAcl {
    fn new(data: &[u8], args: &mut HostStack) -> Self {
        let handle = u16::from_le_bytes(data[0..2].try_into().unwrap());
        HciAcl {
            handle: handle & 0xfff,
            pb_flag: ((handle >> 12) & 0x3) as u8,
            bc_flag: (handle >> 14) as u8,
            data_len: u16::from_le_bytes(data[2..4].try_into().unwrap()),
            data: L2cap::new(&data[4..], args),
        }
    }

    fn as_json(&self, start_byte: u8) -> String {
        let handle_s =
            ParseBitsNode::new(start_byte, 2, 0, 12).format("Handle", self.handle, "", "");
        let pb_flag_s =
            ParseBitsNode::new(start_byte + 1, 1, 12, 2).format("PB Flag", self.pb_flag, "", "");
        let bc_flag_s =
            ParseBitsNode::new(start_byte + 1, 1, 14, 2).format("BC Flag", self.bc_flag, "", "");
        let data_len_s = ParseBytesNode::new(start_byte + 2, 2).format(
            "Data Totlal Length",
            self.data_len,
            "",
            "",
        );
        let data_s = self.data.as_json(start_byte + 4);
        format!(
            r#""ACL": {{{}, {}, {}, {}, {}}}"#,
            handle_s, pb_flag_s, bc_flag_s, data_len_s, data_s
        )
    }
}

#[derive(Debug)]
pub struct HciEvt {
    code: u8,
    len: u8,
    param: HciEvtParam,
}

impl ParseNode for HciEvt {
    fn new(data: &[u8]) -> Self {
        let code = data[0];
        HciEvt {
            code,
            len: data[1],
            param: HciEvtParam::new(&data[2..], code),
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let code_name_s = match self.code {
            0x0e => "HCI_Command_Complete",
            _ => "Unknown",
        };

        let code_s =
            ParseBytesNode::new(start_byte, 1).format("Event Code", self.code, code_name_s, "");
        let len_s = ParseBytesNode::new(start_byte + 1, 1).format(
            "Parameter Total Length",
            self.len,
            "",
            "",
        );
        let param_s = self.param.as_json(start_byte + 2);
        format!(r#""EVT": {{{}, {}, {}}}"#, code_s, len_s, param_s)
    }
}

#[derive(Debug)]
enum HciEvtParam {
    Undefined,
    CommandComplete(EvtCommandComplete),
}

impl HciEvtParam {
    fn new(data: &[u8], code: u8) -> Self {
        match code {
            0x0e => HciEvtParam::CommandComplete(EvtCommandComplete::new(data)),
            _ => HciEvtParam::Undefined,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        match self {
            HciEvtParam::CommandComplete(evt) => evt.as_json(start_byte),
            _ => "".to_string(),
        }
    }
}

#[derive(Debug)]
struct EvtCommandComplete {
    num_hci_command_packets: u8,
    command_opcode: u16,
    // return Depends on command
}

impl ParseNode for EvtCommandComplete {
    fn new(data: &[u8]) -> Self {
        EvtCommandComplete {
            num_hci_command_packets: data[0],
            command_opcode: u16::from_le_bytes([data[1], data[2]]),
        }
    }

    fn as_json(&self, start_byte: u8) -> String {
        let fake = HciCmd::fake_new(self.command_opcode);
        let num_hci_command_packets_s = ParseBytesNode::new(start_byte, 1).format(
            "Num_HCI_Command_Packets",
            self.num_hci_command_packets,
            "",
            "",
        );
        let opcode_s =
            ParseBytesNode::new(start_byte + 1, 2).format("Opcode", self.command_opcode, "", "");
        let opcode_ogf_s = ParseBytesNode::new(start_byte + 2, 1).format(
            "Opcode Group Field (OGF)",
            opcode_to_ogf(self.command_opcode),
            fake.param.get_ogf_name(),
            "",
        );
        let opcode_ocf_s = ParseBytesNode::new(start_byte + 1, 2).format(
            "Opcode Command Field (OCF)",
            opcode_to_ocf(self.command_opcode),
            fake.param.get_ocf_name(),
            "",
        );
        format!(
            "{}, Command_Opcode: {{{}, {}, {}}}",
            num_hci_command_packets_s, opcode_s, opcode_ogf_s, opcode_ocf_s
        )
    }
}

pub fn parse(data: &[u8], args: &mut HostStack) -> String {
    let ret = HciPacket::new(data, args);
    println!("ret={:?}\n", ret);

    ret.as_json(0)
}

fn opcode_to_ogf(opcode: u16) -> u8 {
    (opcode & 0x3ff) as u8
}

fn opcode_to_ocf(opcode: u16) -> u8 {
    (opcode >> 10) as u8
}

// #[cfg(test)]
// mod tests {
//     use crate::str_to_array;

//     use super::*;
//     #[test]
//     fn hci_cmd_reset_test() {
//         let cmd = str_to_array("03 0c 00");
//         let res = HciPacket::new(1, &cmd, &mut args);
//         let expect = HciPacket::Cmd(HciCmd::ControllerAndBaseband(OgfControllerAndBaseband::Reset(OcfReset{header:HciCmdHeader { opcode: (), param_len: () }})))
//         // assert!(res, )
//     }
// }
