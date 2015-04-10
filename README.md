# python-rtsp-client
A rtsp client write in python

    Usage: rtsp-client.py [options] url
    
    In running, you can control play by input "forward","backward","begin","live","pause"
    or "play" with "range" and "scale" parameter, such as "play range:npt=beginning- scale:2"
    You can input "exit","teardown" or ctrl+c to quit
    
    
    Options:
      -h, --help            show this help message and exit
      -t TRANSPORT, --transport=TRANSPORT
                            Set transport type when SETUP: tcp, udp, tcp_over_rtp,
                            udp_over_rtp[default]
      -d DEST_IP, --dest_ip=DEST_IP
                            Set dest ip of udp data transmission, default use same
                            ip with rtsp
      -p CLIENT_PORT, --client_port=CLIENT_PORT
                            Set client port range of udp, default is "10014-10015"
      -n NAT, --nat=NAT     Add "x-NAT" when DESCRIBE, arg format
                            "192.168.1.100:20008"
      -r, --arq             Add "x-zmssRtxSdp:yes" when DESCRIBE
      -f, --fec             Add "x-zmssFecCDN:yes" when DESCRIBE
