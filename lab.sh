#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

lab=.lab
image_url=https://cloud-images.ubuntu.com/releases/24.04/release
image_name=ubuntu-24.04-server-cloudimg-amd64.img
ssg_url=http://archive.ubuntu.com/ubuntu/pool/universe/s/scap-security-guide/ssg-debderived_0.1.79-1_all.deb
ssg_sha256=e1a82dcf58576d8c92fa6c4eb38f5d73153fc05c3c2b51f35b9e30b83240d674

ssh_lab() {
  ssh -F "$lab/ssh_config" lab "$@"
}

fetch() {
  mkdir -p "$lab"
  if [ -n "${LAB_IMAGE:-}" ]; then
    ln -sf "$(realpath "$LAB_IMAGE")" "$lab/base.img"
  elif [ ! -f "$lab/base.img" ]; then
    curl -fsSL -o "$lab/SHA256SUMS" "$image_url/SHA256SUMS"
    curl -fSL -o "$lab/$image_name" "$image_url/$image_name"
    (cd "$lab" && grep " \*$image_name\$" SHA256SUMS | sha256sum -c -)
    mv "$lab/$image_name" "$lab/base.img"
  fi
  if [ ! -f "$lab/ssg-ubuntu2404-ds.xml" ]; then
    curl -fsSL -o "$lab/ssg.deb" "$ssg_url"
    echo "$ssg_sha256  $lab/ssg.deb" | sha256sum -c -
    dpkg-deb --fsys-tarfile "$lab/ssg.deb" | tar -xO ./usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml > "$lab/ssg-ubuntu2404-ds.xml"
    rm "$lab/ssg.deb"
  fi
}

wait_ssh() {
  for _ in $(seq 60); do
    if ssh_lab true 2> /dev/null; then
      return 0
    fi
    sleep 15
  done
  echo "lab vm did not come up, check $lab/console.log" >&2
  return 1
}

down() {
  if [ -f "$lab/qemu.pid" ]; then
    pid=$(cat "$lab/qemu.pid")
    kill "$pid" 2> /dev/null || true
    while kill -0 "$pid" 2> /dev/null; do
      sleep 1
    done
    rm -f "$lab/qemu.pid"
  fi
  ssh -F "$lab/ssh_config" -O exit lab 2> /dev/null || true
}

up() {
  fetch
  down
  rm -f "$lab/known_hosts" "$lab/disk.qcow2"
  [ -f "$lab/id_ed25519" ] || ssh-keygen -q -t ed25519 -N "" -C hardening-lab -f "$lab/id_ed25519"
  [ -f "$lab/password" ] || head -c 18 /dev/urandom | base64 | tr -d '/+=' > "$lab/password"
  cat > "$lab/ssh_config" << EOF
Host lab
  HostName 127.0.0.1
  Port 2222
  User ubuntu
  IdentityFile $PWD/$lab/id_ed25519
  IdentitiesOnly yes
  UserKnownHostsFile $PWD/$lab/known_hosts
  StrictHostKeyChecking accept-new
  ConnectTimeout 10
  ControlMaster auto
  ControlPath /tmp/hardening-lab-%C
  ControlPersist 120s
EOF
  cat > "$lab/user-data" << EOF
#cloud-config
hostname: lab
ssh_pwauth: true
disable_root: false
ssh_authorized_keys:
  - $(cat "$lab/id_ed25519.pub")
chpasswd:
  expire: false
  users:
    - name: ubuntu
      password: $(cat "$lab/password")
      type: text
EOF
  printf 'instance-id: hardening-lab-%s\nlocal-hostname: lab\n' "$(date +%s)" > "$lab/meta-data"
  cloud-localds "$lab/seed.img" "$lab/user-data" "$lab/meta-data"
  qemu-img create -q -f qcow2 -F qcow2 -b "$(realpath "$lab/base.img")" "$lab/disk.qcow2" 10G
  accel=tcg
  cpu=max
  if [ -w /dev/kvm ]; then
    accel=kvm
    cpu=host
  fi
  qemu-system-x86_64 -name hardening-lab -machine q35,accel="$accel" -cpu "$cpu" \
    -smp "${LAB_CPUS:-2}" -m "${LAB_MEMORY:-2048}" \
    -drive file="$lab/disk.qcow2",if=virtio \
    -drive file="$lab/seed.img",if=virtio,format=raw \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=net0 \
    -display none -serial file:"$lab/console.log" -daemonize -pidfile "$lab/qemu.pid"
  wait_ssh
  ssh_lab sudo cloud-init status --wait > /dev/null
}

harden() {
  start=$(date +%s)
  ansible-playbook site.yml | tee "$lab/run1.log"
  echo $(($(date +%s) - start)) > "$lab/provision_seconds"
  ansible-playbook site.yml | tee "$lab/run2.log"
  if ! grep -Eq "^lab +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0" "$lab/run2.log"; then
    echo "second run changed something, the playbook is not idempotent" >&2
    return 1
  fi
}

reboot_vm() {
  boot_id=$(ssh_lab cat /proc/sys/kernel/random/boot_id)
  ssh_lab sudo systemctl reboot || true
  ssh -F "$lab/ssh_config" -O exit lab 2> /dev/null || true
  sleep 30
  wait_ssh
  [ "$(ssh_lab cat /proc/sys/kernel/random/boot_id)" != "$boot_id" ]
}

check() {
  python3 -m pytest -q tests --hosts=ssh://lab --ssh-config="$lab/ssh_config" --sudo --junitxml="$lab/tests.xml"
}

scan() {
  ansible-playbook scan.yml -e scan_phase="$1"
}

all() {
  up
  LAB_LOGINS=allowed python3 -m pytest -q tests -k login
  scan before
  harden
  reboot_vm
  check
  scan after
  python3 summary.py
}

case "${1:-}" in
  up | down | harden | check | all) "$1" ;;
  reboot) reboot_vm ;;
  scan) scan "${2:-after}" ;;
  ssh)
    shift
    ssh_lab "$@"
    ;;
  *)
    echo "usage: bash lab.sh up|harden|reboot|check|scan before|scan after|ssh|down|all" >&2
    exit 1
    ;;
esac
