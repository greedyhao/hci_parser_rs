# HCI_PARSER_RS

纯 rust 实现的蓝牙 hci 解析的工具，目前在开发中

## 目前的效果

输入 `[0x03, 0x0c, 0x00]` 可以得到下面的输出

```json
"HCI":{"Opcode":"0xc03", "OCF":"0x3", "OGF":"0x3", "Command":"Reset", "Parameter_Total_Length":"0x0"}
```

## 目前的情况

hci 层的解析

- [x] 添加一个 hci cmd 的解析
- [ ] 添加一个 hci evt 的解析
- [x] 添加一个 hci acl 的解析

l2cap 层的解析

- [x] 添加 signal 的解析
  - [ ] 解析 L2CAP_COMMAND_REJECT_RSP
  - [x] 解析 L2CAP_CONNECTION_REQ
  - [x] 解析 L2CAP_CONNECTION_RSP
  - [ ] 解析 L2CAP_CONFIGURATION_REQ
  - [ ] 解析 L2CAP_CONFIGURATION_RSP
  - [ ] 解析 L2CAP_DISCONNECTION_REQ
  - [ ] 解析 L2CAP_DISCONNECTION_RSP
  - [ ] 解析 L2CAP_ECHO_REQ
  - [ ] 解析 L2CAP_ECHO_RSP
  - [x] 解析 L2CAP_INFORMATION_REQ
  - [ ] 解析 L2CAP_INFORMATION_RSP
  - [ ] 解析 L2CAP_CONNECTION_PARAMETER_UPDATE_REQ
  - [ ] 解析 L2CAP_CONNECTION_PARAMETER_UPDATE_RSP
  - [ ] 解析 L2CAP_LE_CREDIT_BASED_CONNECTION_REQ
  - [ ] 解析 L2CAP_LE_CREDIT_BASED_CONNECTION_RSP
  - [ ] 解析 L2CAP_FLOW_CONTROL_CREDIT_IND
  - [ ] 解析 L2CAP_CREDIT_BASED_CONNECTION_REQ
  - [ ] 解析 L2CAP_CREDIT_BASED_CONNECTION_RSP
  - [ ] 解析 L2CAP_CREDIT_BASED_RECONFIGURE_REQ
  - [ ] 解析 L2CAP_CREDIT_BASED_RECONFIGURE_RSP

