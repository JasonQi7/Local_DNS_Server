# Local_DNS_Server

A local DNS server implemented in Python. With a built-in root server address, the local DNS server handles recursive queries for its clients. Upon each query, the server would reply with A type record, glue records and CNAME records (if any); and every A type record is cached for future queries. 

To start the server, type the following command in terminal:
$ python ./ncsdns.py

The server responds:
./ncsdns.py: listening on port 40229

In a different window, use dig to query the server: 
$ dig @127.0.0.1 -p [port number] [query hostname]

Note: this server does not support IPv6 records and SOA type records.
