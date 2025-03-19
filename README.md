# Packet Latency Tracker
A useful tool to track data packet's processing latency in the Linux kernel via eBPF.

- For TCP packets, the program will track the processing latency from *ip_rcv_core* to *tcp_queue_rcv*.

- For UDP packets, the program will track the processing latency from *ip_rcv_core*
to *__udp_enqueue_schedule_skb*.
# Usage
1) Build the project
```
./build.sh
```
2) Run the tracker
```
make run
```
3) Get the results

The TCP results will be saved to **tcp_packets.log**, and the UDP results will be saved to **udp_packets.log**.

The format is as follows:
- For TCP,
```
sip  sport  dport  seq  ack  latency
...   ...    ...   ...  ...    ...
...   ...    ...   ...  ...    ...
...   ...    ...   ...  ...    ...
```
- For UDP,
```
sip  sport  dport  latency
...   ...    ...     ...
...   ...    ...     ...
...   ...    ...     ...
```