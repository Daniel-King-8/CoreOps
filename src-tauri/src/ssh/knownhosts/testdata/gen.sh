#!/bin/sh
# Builds the OpenSSH reference outputs the known_hosts tests compare
# against: throwaway keys, certificates, known_hosts files, KRLs, and what
# ssh-keygen prints for them. Usage: gen.sh OUTDIR [ssh-keygen]
# The checked-in copy of OUTDIR is this directory's openssh-10.3/.
set -eu
OUT=$1
KG=${2:-ssh-keygen}
mkdir -p "$OUT"
cd "$OUT"
rm -f ./*.pub ./*.txt ./*.bin ca ca2

{ ssh -V 2>&1 || true; } | head -1 > version.txt

key() { "$KG" -q -t "$1" ${3:+-b "$3"} -N "" -C "$2" -f "$2"; rm -f "$2"; }
key ed25519 k_ed1
key ed25519 k_ed2
key ecdsa k_ec256 256
key ecdsa k_ec384 384
key ecdsa k_ec521 521
key rsa k_rsa 2048
key rsa k_rsa1024 1024
"$KG" -q -t ed25519 -N "" -C ca -f ca
"$KG" -q -t ecdsa -N "" -C ca2 -f ca2

# A security key public key cannot be generated without hardware; build one
# by hand (type, 32-byte key, application) so fingerprints can be compared.
{
  printf '\000\000\000\032sk-ssh-ed25519@openssh.com'
  printf '\000\000\000\040'
  printf 'abcdefghijklmnopqrstuvwxyz012345'
  printf '\000\000\000\004ssh:'
} > sk.bin
printf 'sk-ssh-ed25519@openssh.com %s k_sk\n' "$(base64 < sk.bin | tr -d '\n')" > k_sk.pub
rm -f sk.bin

# Host certificates: name, CA, serial, key ID.
cert() {
  "$KG" -q -t ed25519 -N "" -C "$1" -f "$1"; rm -f "$1"
  "$KG" -q -s "$2" -h -n "$1.test" -z "$3" -I "$4" "$1.pub"
  rm -f "$1.pub"
}
cert c_s0 ca 0 plain-id
cert c_s5 ca 5 five
cert c_s150 ca 150 in-range
cert c_s302 ca 302 bitmap-hit
cert c_s303 ca 303 bitmap-miss
cert c_s9000 ca 9000 list-hit
cert c_s1001 ca 1001 not-revoked
cert c_idrev ca 7777 revoked-id
cert c2_s5 ca2 5 other-ca
cert c2_any ca2 4242 any-id
# Only the public halves stay.
rm -f ca ca2

PUBS="k_ed1.pub k_ed2.pub k_ec256.pub k_ec384.pub k_ec521.pub k_rsa.pub k_rsa1024.pub k_sk.pub ca.pub ca2.pub c_s5-cert.pub"
: > fp.txt
for f in $PUBS; do
  for h in sha256 md5; do
    echo "== $f $h" >> fp.txt
    "$KG" -lv -E "$h" -f "$f" >> fp.txt
  done
done

b() { cut -d' ' -f2 "$1"; }
cat > kh.txt <<EOF
# a comment

example.com,192.0.2.1 ssh-ed25519 $(b k_ed1.pub) first comment
[example.com]:2222 ecdsa-sha2-nistp256 $(b k_ec256.pub)
*.wild.test,!bad.wild.test ssh-rsa $(b k_rsa.pub)
@cert-authority *.ca.test ssh-ed25519 $(b ca.pub)
@revoked * ssh-ed25519 $(b k_ed2.pub)
  	indented.test ecdsa-sha2-nistp384 $(b k_ec384.pub)   trailing  comment
UPPER.Test ecdsa-sha2-nistp521 $(b k_ec521.pub)
@bogus host.test ssh-ed25519 $(b k_ed1.pub)
trunc.test
trunc2.test ssh-ed25519
badb64.test ssh-ed25519 AAAA!!!!
mismatch.test ssh-rsa $(b k_ed1.pub)
rsa1.test 1024 35 1234567
q?.test ssh-ed25519 $(b k_ed1.pub)
|1|bad|hash ssh-ed25519 $(b k_ed1.pub)
@revoked	tab.test ssh-ed25519 $(b k_ed1.pub) has a space
@revoked	nospace.test	ssh-ed25519	$(b k_ed1.pub)
dup.test ssh-ed25519 $(b k_ed1.pub)
dup.test ssh-rsa $(b k_rsa.pub)
alias.test rsa-sha2-256 $(b k_rsa.pub)
crlf.test ssh-ed25519 $(b k_ed1.pub)@CRLF@
hc.test #x
neg.test,!neg.test ssh-ed25519 $(b k_ed1.pub)
small.test ssh-rsa $(b k_rsa1024.pub)
@revoked @cert-authority two.test ssh-ed25519 $(b k_ed1.pub)
sk.test sk-ssh-ed25519@openssh.com $(b k_sk.pub)
EOF
# One line ends in CRLF, as after a Windows editor.
awk '{ if (sub(/@CRLF@$/, "")) printf "%s\r\n", $0; else print }' kh.txt > kh.tmp
mv kh.tmp kh.txt
NAMES="example.com 192.0.2.1 [example.com]:2222 a.wild.test bad.wild.test x.ca.test anything.test indented.test upper.test UPPER.Test qa.test qab.test nospace.test tab.test dup.test alias.test crlf.test neg.test trunc.test mismatch.test small.test sk.test two.test host.test"
echo "$NAMES" > names.txt
: > find.txt
for n in $NAMES; do
  echo "== $n" >> find.txt
  "$KG" -F "$n" -l -E sha256 -f kh.txt >> find.txt 2>/dev/null || true
done

# Hashing: ssh-keygen -H rewrites the file in place.
cat > kh_hash.txt <<EOF
plain.test,192.0.2.7 ssh-ed25519 $(b k_ed1.pub) c1
[port.test]:2200 ecdsa-sha2-nistp256 $(b k_ec256.pub)
Mixed.Case.Test ssh-rsa $(b k_rsa.pub)
*.wild.test ssh-ed25519 $(b k_ed2.pub)
@cert-authority *.ca.test ssh-ed25519 $(b ca.pub)
EOF
cp kh_hash.txt kh_hashed.txt
"$KG" -H -f kh_hashed.txt > /dev/null 2>&1
rm -f kh_hashed.txt.old
HNAMES="plain.test 192.0.2.7 [port.test]:2200 mixed.case.test Mixed.Case.Test x.wild.test x.ca.test other.test"
echo "$HNAMES" > hnames.txt
: > find_hashed.txt
for n in $HNAMES; do
  echo "== $n" >> find_hashed.txt
  "$KG" -F "$n" -l -E sha256 -f kh_hashed.txt >> find_hashed.txt 2>/dev/null || true
done

# Removal: ssh-keygen -R drops the plain lines for a host, as
# hostfile_replace_entries does with no keys to keep.
cat > kh_del.txt <<EOF
# keep me
a.test,192.0.2.9 ssh-ed25519 $(b k_ed1.pub)
b.test ssh-rsa $(b k_rsa.pub)
a.test ecdsa-sha2-nistp256 $(b k_ec256.pub)
@revoked a.test ssh-ed25519 $(b k_ed2.pub)
@cert-authority a.test ssh-ed25519 $(b ca.pub)
*.test ssh-ed25519 $(b k_ed2.pub)
EOF
cat kh_hashed.txt >> kh_del.txt
DNAMES="a.test 192.0.2.9 b.test plain.test c.test"
echo "$DNAMES" > dnames.txt
i=0
for n in $DNAMES; do
  i=$((i + 1))
  cp kh_del.txt "del_$i.txt"
  "$KG" -R "$n" -f "del_$i.txt" > /dev/null 2>&1 || true
  rm -f "del_$i.txt.old"
done

# KRLs. Serials 300..340 in steps of two come out as a bitmap section,
# 100-200 as a range, 5 and 9000 and 70000 as a list.
{
  echo "serial: 5"
  echo "serial: 100-200"
  s=300; while [ $s -le 340 ]; do echo "serial: $s"; s=$((s + 2)); done
  echo "serial: 9000"
  echo "serial: 70000"
  echo "id: revoked-id"
  echo "key: $(cat k_ed2.pub)"
  echo "sha1: $(cat k_ec256.pub)"
  echo "sha256: $(cat k_ec384.pub)"
  echo "hash: $("$KG" -l -E sha256 -f k_rsa1024.pub | cut -d' ' -f2)"
} > krl_spec.txt
"$KG" -q -k -f krl_ca.bin -z 7 -s ca.pub krl_spec.txt
# ssh-keygen only writes CA-specific key ID revocations, so the
# any-CA ("wildcard") section is written by hand: header, then a
# certificate section with an empty CA and one key ID, "any-id".
{
  printf 'SSHKRL\n\000'
  printf '\000\000\000\001'
  printf '\000\000\000\000\000\000\000\001'
  printf '\000\000\000\000\000\000\000\000'
  printf '\000\000\000\000\000\000\000\000'
  printf '\000\000\000\000'
  printf '\000\000\000\011hand-made'
  printf '\001\000\000\000\027'
  printf '\000\000\000\000\000\000\000\000'
  printf '\043\000\000\000\012\000\000\000\006any-id'
} > krl_any.bin
"$KG" -q -k -f krl_carev.bin ca.pub
"$KG" -Q -l -f krl_ca.bin > krl_ca_dump.txt 2>&1 || true

QUERY="k_ed1.pub k_ed2.pub k_ec256.pub k_ec384.pub k_ec521.pub k_rsa.pub k_rsa1024.pub ca.pub ca2.pub c_s0-cert.pub c_s5-cert.pub c_s150-cert.pub c_s302-cert.pub c_s303-cert.pub c_s9000-cert.pub c_s1001-cert.pub c_idrev-cert.pub c2_s5-cert.pub c2_any-cert.pub"
echo "$QUERY" > query.txt
for k in krl_ca krl_any krl_carev; do
  : > "q_$k.txt"
  for q in $QUERY; do
    "$KG" -Q -f "$k.bin" "$q" >> "q_$k.txt" 2>&1 || true
  done
done
