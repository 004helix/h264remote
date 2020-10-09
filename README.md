# h264send / h264feed

H264/HEVC remote camera access kit for slow and/or unstable connections

Send example:
```
$ ffmpeg -nostdin -hide_banner -nostats -rtsp_transport tcp -stimeout 5000000 \
  -i rtsp://<camera-ip>:554/user=admin_password=_channel=1_stream=1.sdp -c:v copy -f h264 - | \
  h264send -a <feed-ip> -p <feed-port> -k <encryption-key> -s 1048576
```

Feed example:
```
$ h264feed -a <listen-ip> -p <listen-port> -k <encryption-key> | \
  ffmpeg -nostdin -hide_banner -nostats -format h264 -i - -c:v mjpeg -global_quality 85 -f mpjpeg - | \
  ffmpjpeg-httpd -a 127.0.0.1 -p 8080
```

The main idea is:

on sender:
 - get H264/HEVC NAL byte stream on stdin from ffmpeg
 - divide it to frames (VPS + PPS + SPS + I-frame / P-frame; there is no support for B-frames)
 - prepend each frame with the timestamp when it was received from stdin
 - encrypt data with chacha20 stream cipher and send it too feeder
 - if connection to feeder has closed (or send buffer has overflowed):
   - reconnect, skippinng any frames from stdin
   - wait the next I-frame (prepended with VPS, PPS and SPS units)
   - send "new" stream

on feeder:
 - accept and authenticate connection from sender
 - receive and decrypt frames
 - send frames to stdout keeping pause between frames according to timestamps from sender
 - if new connection from sender was authenticated, all old connections will be closed (if any)
