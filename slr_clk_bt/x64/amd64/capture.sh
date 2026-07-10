#!/bin/bash
BASE=/mnt/d/Downloads/Vyft_product/Slura/slr_clk_bt/x64/amd64
ESP=$BASE/esp
VARS=$BASE/OVMF_VARS_4M.fd
CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
rm -f /tmp/shot.ppm /tmp/qemu_out.log /tmp/serial_cap.log
setsid qemu-system-x86_64 -nodefaults -machine q35,accel=kvm:tcg -m 1024M \
  -device virtio-vga -display none \
  -device qemu-xhci,id=xhci -device usb-tablet,bus=xhci.0 -device usb-mouse,bus=xhci.0 -device usb-kbd,bus=xhci.0 \
  -drive if=pflash,format=raw,readonly=on,file="$CODE" \
  -drive if=pflash,format=raw,file="$VARS" \
  -drive if=ide,format=raw,file=fat:rw:"$ESP" \
  -serial file:/tmp/serial_cap.log \
  -monitor tcp:127.0.0.1:55557,server,nowait -no-reboot -no-shutdown >/tmp/qemu_out.log 2>&1 &
QPID=$!
echo "qemu pid=$QPID"
sleep 9
{ printf 'sendkey ret\n'; sleep 26; printf 'screendump /tmp/shot.ppm\n'; sleep 3; printf 'quit\n'; sleep 1; } | (exec 3<>/dev/tcp/127.0.0.1/55557 && cat >&3)
sleep 1
kill $QPID 2>/dev/null
cp -f /tmp/serial_cap.log "$BASE/serial_cap.log" 2>/dev/null
if [ -f /tmp/shot.ppm ]; then echo CAPTURE_OK; cp /tmp/shot.ppm "$BASE/shot.ppm"; else echo NO_CAPTURE; head -5 /tmp/qemu_out.log; fi
