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
