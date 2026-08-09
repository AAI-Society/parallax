#!/usr/bin/env bash
# Establish, on real hardware, whether a TDX guest can extend RTMR3.
#
#   ./scripts/spike-rtmr.sh <output-dir>
#
# Run this ON a TDX guest (a GCP C3 created with --confidential-compute-type=TDX,
# or equivalent). `scripts/spike-rtmr-on-gcp.sh` provisions one, copies this
# over, runs it, brings the results home and deletes the VM.
#
# This is a probe, not a build step, so it does not `set -e`: an interface that
# is absent, or an ioctl that returns ENOTTY, is the *answer* to the question
# being asked and must be recorded rather than abort the run. Every step
# therefore reports its own exit status into the transcript, and the script
# reaches the end on every path. It is safe to re-run: each run works in a
# fresh, pid-named configfs directory and writes only inside <output-dir>.
#
# What it produces in <output-dir>:
#   transcript.txt      every command run, with its exit status and raw output
#   quote-before.bin    a quote taken before any extension attempt
#   quote-after.bin     a quote taken after the first extension of DIGEST
#   quote-after2.bin    a quote taken after extending the same DIGEST again
#   extended-digest.bin the 48 raw bytes that were extended
#   rtmr3-*.hex         the RTMR3 field sliced out of each of the three quotes
#   captured-at, provider, host.txt
#
# Nothing here synthesises a quote or a measurement. If the hardware will not
# do it, the transcript says so and the fixtures for that step are absent.
set -uo pipefail

OUT="${1:?usage: spike-rtmr.sh <output-dir>}"
mkdir -p "$OUT"
TRANSCRIPT="$OUT/transcript.txt"
: > "$TRANSCRIPT"

# The digest extended into RTMR3. A fixed string, so that the same 48 bytes go
# in on every instance and every boot — question 3 (is extension deterministic?)
# is only answerable if the input is identical across runs. SHA-384 because that
# is the RTMR measurement algorithm; TDG.MR.RTMR.EXTEND takes exactly 48 bytes.
SPIKE_STRING='parallax-attest-spike-v1'

# Offsets into a DCAP v4 quote. The header is 48 bytes and the TD report body
# follows, so a field at body offset N lives at absolute N+48. Recorded both
# ways because the two are easy to confuse and the difference is a silent
# wrong-field bug: `ov-poc-standard/impl/poc/tdx.py` tabulates body offsets and
# adds `_HDR` separately.
BODY_OFF=48
RTMR3_BODY=472      # -> absolute 520
MRTD_BODY=136       # -> absolute 184
RTMR3_ABS=$((BODY_OFF + RTMR3_BODY))
MRTD_ABS=$((BODY_OFF + MRTD_BODY))

# ---------------------------------------------------------------------------
# transcript helpers
# ---------------------------------------------------------------------------

section() {
  {
    echo
    echo "==============================================================="
    echo "== $*"
    echo "==============================================================="
  } | tee -a "$TRANSCRIPT"
}

# run "<shell command>" — records the command, its output and its exit status.
# The status is recorded because for most of this script a non-zero status is
# the finding, not a failure.
run() {
  local cmd="$1" status
  {
    echo
    echo "\$ $cmd"
  } | tee -a "$TRANSCRIPT"
  # Interleave stderr into stdout: the errno an interface returns is the point.
  eval "$cmd" 2>&1 | tee -a "$TRANSCRIPT"
  status="${PIPESTATUS[0]}"
  echo "[exit $status]" | tee -a "$TRANSCRIPT"
  return "$status"
}

note() { echo "$*" | tee -a "$TRANSCRIPT"; }

# ---------------------------------------------------------------------------
# quote capture, via configfs-tsm — the interface that is already known to work
# ---------------------------------------------------------------------------

# take_quote <destination> — writes a quote over 64 zero bytes of report_data.
# report_data is zeroed on purpose: this spike is about RTMR3, and holding
# report_data constant means any difference between two quotes is attributable
# to the measurement registers rather than to the binding field.
take_quote() {
  local dest="$1" tsm status
  tsm="/sys/kernel/config/tsm/report/spike-$$-$RANDOM"
  if ! sudo mkdir "$tsm" 2>>"$TRANSCRIPT"; then
    note "take_quote: could not create $tsm"
    return 1
  fi
  sudo dd if=/dev/zero of="$tsm/inblob" bs=64 count=1 status=none
  sudo cat "$tsm/outblob" > "$dest"
  status=$?
  sudo cat "$tsm/provider" 2>/dev/null | tr -d '\n' > "$OUT/provider"
  # configfs report directories are single-use on some kernels — `inblob` cannot
  # be rewritten once `outblob` has been read — so each quote gets a fresh one
  # and it is removed immediately rather than left for the next call to reuse.
  sudo rmdir "$tsm" 2>/dev/null
  if [ "$status" -ne 0 ] || [ ! -s "$dest" ]; then
    note "take_quote: $dest not produced (status $status)"
    return 1
  fi
  note "take_quote: wrote $dest ($(stat -c%s "$dest") bytes)"
  return 0
}

# field <quote> <absolute-offset> <length> — hex of one quote field.
field() {
  dd if="$1" bs=1 skip="$2" count="$3" status=none 2>/dev/null | xxd -p | tr -d '\n'
}

# ---------------------------------------------------------------------------
# Step 2: enumerate what the guest exposes
# ---------------------------------------------------------------------------

section "Step 2: what the guest exposes"

# GCP images mount configfs already, but the mount is idempotent and a bare
# image may not.
sudo mount -t configfs none /sys/kernel/config 2>/dev/null

run 'uname -a'
run 'grep -m1 "^model name" /proc/cpuinfo'
run 'cat /etc/os-release | head -3'
run 'ls -la /sys/kernel/config/tsm/'
run 'ls -laR /sys/kernel/config/tsm/'
run 'ls -la /dev/tdx_guest /dev/tpm0 /dev/tpmrm0'
run 'ls -la /sys/class/tpm/'
run 'sudo dmesg | grep -i "tdx\|tsm" | head -20'

# The decisive enumeration. If the kernel exposes a writable measurement
# register anywhere, its name contains "rtmr" or it sits under a "measurements"
# directory; searching for both is cheaper and more honest than guessing a path.
run 'find /sys /dev -iname "*rtmr*" 2>/dev/null'
run 'find /sys -type d -name "measurement*" 2>/dev/null'
run 'ls -la /sys/class/misc/tdx_guest/ 2>&1'

# What the running kernel actually implements, independent of what any manual
# page claims. TDG.MR.RTMR.EXTEND is issued by a kernel symbol; if no such
# symbol is linked in, no interface can be reaching the TDX module.
run 'sudo grep -i "rtmr\|tsm_mr\|tdx_mcall" /proc/kallsyms | head -20'
run 'ls /usr/include/asm/tdx.h && cat /usr/include/asm/tdx.h'

{
  uname -r
  grep -m1 "^model name" /proc/cpuinfo
  sudo dmesg 2>/dev/null | grep -i -m3 tdx
} > "$OUT/host.txt" 2>/dev/null

# ---------------------------------------------------------------------------
# Question 1: can RTMR3 be extended, and through which interface?
# ---------------------------------------------------------------------------

section "Q1: is there an extension interface?"

printf '%s' "$SPIKE_STRING" | sha384sum | cut -d' ' -f1 > "$OUT/extended-digest.hex"
xxd -r -p "$OUT/extended-digest.hex" > "$OUT/extended-digest.bin"
note "digest to extend = SHA-384(\"$SPIKE_STRING\") = $(cat "$OUT/extended-digest.hex")"
note "extended-digest.bin is $(stat -c%s "$OUT/extended-digest.bin") bytes"

# --- Candidate 1: configfs-tsm ---------------------------------------------
# Known to serve quote generation. Whether it also offers extension is the
# question; a write-capable attribute would show up in the directory listing.
section "Q1 candidate 1: configfs-tsm"
run 'ls -la /sys/kernel/config/tsm/'
run 'sudo mkdir -p /sys/kernel/config/tsm/report/probe-'"$$"' && ls -la /sys/kernel/config/tsm/report/probe-'"$$"
run 'sudo rmdir /sys/kernel/config/tsm/report/probe-'"$$"' 2>/dev/null; true'

# --- Candidate 2: the tsm-mr / misc-device sysfs measurement registers ------
# The Linux measurement-register interface, when present, exposes each RTMR as a
# sysfs attribute; writing 48 bytes to an extendable one issues the extend.
section "Q1 candidate 2: sysfs measurement registers"
MR_DIR=""
for d in /sys/class/misc/tdx_guest/measurements \
         /sys/devices/virtual/misc/tdx_guest/measurements; do
  if [ -d "$d" ]; then MR_DIR="$d"; break; fi
done
if [ -z "$MR_DIR" ]; then
  note "no measurement-register directory at either known path"
else
  note "measurement registers at $MR_DIR"
  run "ls -la $MR_DIR"
  for f in "$MR_DIR"/*rtmr3*; do
    [ -e "$f" ] || continue
    note "candidate RTMR3 attribute: $f (mode $(stat -c%a "$f"))"
    RTMR3_ATTR="$f"
  done
fi

# --- Candidate 3: the /dev/tdx_guest ioctl ---------------------------------
# Upstream Linux exports TDX_CMD_GET_REPORT0 on this device. Earlier
# out-of-tree drivers also carried an extend ioctl. Rather than assert which,
# probe the 'T' ioctl space and record the errno each number returns: ENOTTY
# means the running driver has no such command, and that is a finding.
section "Q1 candidate 3: /dev/tdx_guest ioctl"
if [ ! -e /dev/tdx_guest ]; then
  note "/dev/tdx_guest does not exist"
else
  run 'sudo apt-get install -y -q gcc >/dev/null 2>&1; gcc --version | head -1'
  cat > "$OUT/ioctl-probe.c" <<'PROBE'
/* Probe the ioctl space of /dev/tdx_guest and report what each command does.
 *
 * Two things are being established. First, that the device works at all:
 * TDX_CMD_GET_REPORT0 (_IOWR('T', 1, struct tdx_report_req)) is the one
 * command upstream Linux documents, and it must succeed or nothing below
 * means anything. Second, whether any *other* command in the 'T' space is
 * implemented — an extend ioctl, if the running driver has one, lives there.
 *
 * ENOTTY from a command number means the driver's switch has no case for it.
 * The probe passes a zeroed 4 KiB buffer to every speculative command, which
 * is larger than any plausible argument struct, so a driver that does accept
 * one cannot be made to read past the end of the allocation.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

#define TDX_REPORTDATA_LEN 64
#define TDX_REPORT_LEN     1024

struct tdx_report_req {
    uint8_t reportdata[TDX_REPORTDATA_LEN];
    uint8_t tdreport[TDX_REPORT_LEN];
};

#define TDX_CMD_GET_REPORT0 _IOWR('T', 1, struct tdx_report_req)

int main(void)
{
    int fd = open("/dev/tdx_guest", O_RDWR | O_SYNC);
    if (fd < 0) {
        printf("open(/dev/tdx_guest) failed: %s\n", strerror(errno));
        return 1;
    }

    struct tdx_report_req req;
    memset(&req, 0, sizeof(req));
    if (ioctl(fd, TDX_CMD_GET_REPORT0, &req) == 0)
        printf("TDX_CMD_GET_REPORT0  _IOWR('T',1,...)  OK "
               "(tdreport[0..3] = %02x %02x %02x %02x)\n",
               req.tdreport[0], req.tdreport[1],
               req.tdreport[2], req.tdreport[3]);
    else
        printf("TDX_CMD_GET_REPORT0  _IOWR('T',1,...)  errno=%d (%s)\n",
               errno, strerror(errno));

    /* Sweep the rest of the 'T' space in all four direction encodings. An
     * extend ioctl in any historical driver would be reachable from here. */
    static unsigned char arg[4096];
    const char *dirname_[4] = { "_IO  ", "_IOW ", "_IOR ", "_IOWR" };
    const unsigned dir[4] = { _IOC_NONE, _IOC_WRITE, _IOC_READ,
                              _IOC_READ | _IOC_WRITE };
    /* Sizes of every argument struct an extend command plausibly takes:
     * 48-byte digest alone, digest + index, and a page. */
    const unsigned sizes[4] = { 0, 48, 56, 64 };

    for (unsigned nr = 2; nr <= 8; nr++) {
        for (int d = 0; d < 4; d++) {
            for (int s = 0; s < 4; s++) {
                memset(arg, 0, sizeof(arg));
                unsigned long cmd = _IOC(dir[d], 'T', nr, sizes[s]);
                errno = 0;
                int rc = ioctl(fd, cmd, arg);
                if (rc == 0 || errno != ENOTTY)
                    printf("%s('T',%u,size=%u) cmd=0x%lx rc=%d errno=%d (%s)\n",
                           dirname_[d], nr, sizes[s], cmd, rc, errno,
                           rc == 0 ? "OK" : strerror(errno));
            }
        }
    }
    printf("sweep done: any 'T' command not printed above returned ENOTTY "
           "(no such command in this driver)\n");
    close(fd);
    return 0;
}
PROBE
  run "gcc -O0 -Wall -o $OUT/ioctl-probe $OUT/ioctl-probe.c"
  run "sudo $OUT/ioctl-probe"
fi

# --- Candidate 4: a vTPM ----------------------------------------------------
# GCP Confidential VMs generally expose a vTPM, and TDX RTMRs are sometimes
# described as mapping onto TPM PCRs 1-3. Whether *this* platform wires a PCR
# extend through to an RTMR is the thing to test, and the test is not that the
# PCR changed — it is whether the quote's RTMR3 changed, which Q2 checks.
section "Q1 candidate 4: vTPM"
run 'ls -la /dev/tpm* 2>&1'
if [ -e /dev/tpm0 ] || [ -e /dev/tpmrm0 ]; then
  run 'sudo apt-get install -y -q tpm2-tools >/dev/null 2>&1; tpm2_pcrread --version 2>&1 | head -1'
  run 'sudo tpm2_pcrread sha256:1,2,3 2>&1'
else
  note "no TPM character device; nothing to extend through"
fi

# ---------------------------------------------------------------------------
# Question 2: does an extended value appear in a subsequent quote's RTMR3?
# Question 3: is it deterministic, and is a second extension a hash chain?
# ---------------------------------------------------------------------------

section "Q2/Q3: quote, extend, quote, extend, quote"

take_quote "$OUT/quote-before.bin"
if [ -s "$OUT/quote-before.bin" ]; then
  field "$OUT/quote-before.bin" "$RTMR3_ABS" 48 > "$OUT/rtmr3-before.hex"
  field "$OUT/quote-before.bin" "$MRTD_ABS" 48 > "$OUT/mrtd.hex"
  note "RTMR3 before (abs offset $RTMR3_ABS) = $(cat "$OUT/rtmr3-before.hex")"
  note "MRTD        (abs offset $MRTD_ABS) = $(cat "$OUT/mrtd.hex")"
  # The brief cites 472 for RTMR3, which is the *body* offset; dumping the
  # field at the absolute reading of the same number too makes the mix-up
  # visible in the transcript rather than silently producing the wrong bytes.
  note "bytes at absolute $RTMR3_BODY (body offset read as absolute, for comparison) = $(field "$OUT/quote-before.bin" "$RTMR3_BODY" 48)"
fi

# extend_rtmr3 <label> — the one place an extension is actually attempted.
# Returns 0 only if a write was accepted; every refusal is transcribed.
extend_rtmr3() {
  local label="$1"
  section "extension attempt: $label"
  if [ -n "${RTMR3_ATTR:-}" ]; then
    note "writing 48 bytes to $RTMR3_ATTR"
    if run "sudo dd if=$OUT/extended-digest.bin of=$RTMR3_ATTR bs=48 count=1 status=none"; then
      note "RESULT: write to $RTMR3_ATTR was accepted"
      run "sudo xxd -p $RTMR3_ATTR | tr -d '\n'; echo"
      return 0
    fi
    note "RESULT: write to $RTMR3_ATTR was refused"
    return 1
  fi
  note "RESULT: no writable RTMR3 interface was found, so nothing to extend"
  return 1
}

extend_rtmr3 "first extension of the spike digest"
FIRST_EXTEND=$?

take_quote "$OUT/quote-after.bin"
if [ -s "$OUT/quote-after.bin" ]; then
  field "$OUT/quote-after.bin" "$RTMR3_ABS" 48 > "$OUT/rtmr3-after.hex"
  note "RTMR3 after first extension = $(cat "$OUT/rtmr3-after.hex")"
fi

extend_rtmr3 "second extension of the SAME digest, same boot"
SECOND_EXTEND=$?

take_quote "$OUT/quote-after2.bin"
if [ -s "$OUT/quote-after2.bin" ]; then
  field "$OUT/quote-after2.bin" "$RTMR3_ABS" 48 > "$OUT/rtmr3-after2.hex"
  note "RTMR3 after second extension = $(cat "$OUT/rtmr3-after2.hex")"
fi

# ---------------------------------------------------------------------------
# verdict, computed from the bytes rather than from the attempts
# ---------------------------------------------------------------------------

section "verdict"
note "first extension attempt exit status:  $FIRST_EXTEND (0 = accepted)"
note "second extension attempt exit status: $SECOND_EXTEND (0 = accepted)"

b="$(cat "$OUT/rtmr3-before.hex" 2>/dev/null)"
a1="$(cat "$OUT/rtmr3-after.hex" 2>/dev/null)"
a2="$(cat "$OUT/rtmr3-after2.hex" 2>/dev/null)"

if [ -z "$b" ] || [ -z "$a1" ]; then
  note "Q2: UNDETERMINED — did not obtain two quotes to compare"
elif [ "$b" = "$a1" ]; then
  note "Q2: NO — RTMR3 is unchanged in the quote taken after the extension."
  note "    Either no extension happened, or it did not reach the quote."
else
  note "Q2: YES — RTMR3 changed in the quote taken after the extension."
fi

if [ -z "$a1" ] || [ -z "$a2" ]; then
  note "Q3 (hash chain): UNDETERMINED"
elif [ "$a1" = "$a2" ]; then
  note "Q3 (hash chain): NO — extending the same digest twice in one boot left"
  note "    RTMR3 unchanged. That is not a hash chain and the second extension"
  note "    did not take effect."
else
  note "Q3 (hash chain): YES — a second extension of the same digest produced a"
  note "    different RTMR3, as a hash chain must."
fi
note "Q3 (across boots) is answered by running this script on a second, freshly"
note "booted instance and comparing rtmr3-after.hex."
note "Q4 is answered by comparing mrtd.hex between instances."

date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/captured-at"
note "captured at $(cat "$OUT/captured-at")"
note "transcript is $TRANSCRIPT"
