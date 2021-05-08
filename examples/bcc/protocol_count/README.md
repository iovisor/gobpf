# usage

1 In current directory (example/bcc/protocol_count)

```bash
go build net_protocol.go
sudo ./net_protocol
```

2  Open another terminal

```bash
ping 127.0.0.1 -c 10
```

3  Result

```
TCP: 0, UDP: 0, ICMP: 0
TCP: 0, UDP: 0, ICMP: 4
TCP: 0, UDP: 0, ICMP: 24
TCP: 0, UDP: 0, ICMP: 40
TCP: 0, UDP: 0, ICMP: 40
TCP: 0, UDP: 0, ICMP: 40
TCP: 4, UDP: 0, ICMP: 40
```

# Misc

Since we  run ping for the loop interface, there are  4 packets for one ping including( egress  send, ingress receive, egress reply and ingress reply)


