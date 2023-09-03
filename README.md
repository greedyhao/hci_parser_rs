# HCI_PARSER_RS

纯 rust 实现的蓝牙 hci 解析的工具，目前在开发中

## 目前的效果

输入 `[0x03, 0x0c, 0x00]` 可以得到下面的输出

```json
{"Opcode":"0xc03", "OCF":"0x3", "OGF":"0x3", "Command":"Reset", "Parameter_Total_Length":"0x0"}
```

## 预计的工作

hci 层的解析

- [ ] 完善剩余的 hci cmd 的解析
- [ ] 规划 hci evt 的解析
- [ ] 规划 hci acl 的解析
