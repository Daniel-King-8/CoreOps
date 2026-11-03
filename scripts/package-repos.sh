#!/usr/bin/env bash
# Signed package repositories for a release, so Linux users can
#   apt install reach   /   dnf install reach
# and get updates with their system's own upgrade.
#
#   package-repos.sh <dir-with-the-.deb-and-.rpm> <out-dir> <base-url-of-the-packages>
#
# Signing key: the secret key is read from $REPO_GPG_PRIVATE_KEY (armored)
# and its passphrase from $REPO_GPG_PASSPHRASE. It is imported into a
# throwaway GNUPGHOME that is deleted on exit, so it never touches a disk
# outside this run.
#
# APT: a flat repository (Debian's "flat repository format": no dists/ or
# pool/, the index next to the packages). The index files are uploaded
# into the GitHub release beside the .deb, so the source line is
#   deb [signed-by=…] https://github.com/OWNER/REPO/releases/latest/download ./
# and `latest` always serves the newest release. InRelease is the index
# signed inline; apt checks it against the key the user installed with
# signed-by, and the .deb against the SHA-256 in it.
#
# DNF: repodata/ cannot be a release asset (asset names have no folders),
# so it goes to the website; its <location> entries point at the .rpm in
# the release (createrepo_c --location-prefix). repomd.xml is signed
# (repo_gpgcheck), which covers every package checksum listed in it.
set -euo pipefail

pkgs=$1
out=$2
base=${3%/}

: "${REPO_GPG_PRIVATE_KEY:?the signing key is missing}"
: "${REPO_GPG_PASSPHRASE:?the signing key passphrase is missing}"

export GNUPGHOME
GNUPGHOME=$(mktemp -d)
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT
chmod 700 "$GNUPGHOME"
printf '%s\n' "$REPO_GPG_PRIVATE_KEY" | gpg --batch --quiet --import
fpr=$(gpg --batch --with-colons --list-secret-keys | awk -F: '/^fpr/ {print $10; exit}')
[ -n "$fpr" ] || { echo "No secret key was imported" >&2; exit 1; }

sign() { # sign <args…>: gpg with the passphrase on its own descriptor, never argv
	gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 --local-user "$fpr" "$@" 3<<<"$REPO_GPG_PASSPHRASE"
}

mkdir -p "$out/apt" "$out/rpm"

# ---- APT ------------------------------------------------------------------
deb=$(ls "$pkgs"/*.deb | head -1)
cp "$deb" "$out/apt/"
(
	cd "$out/apt"
	apt-ftparchive packages . > Packages
	gzip -9kn Packages
	apt-ftparchive \
		-o APT::FTPArchive::Release::Origin=Reach \
		-o APT::FTPArchive::Release::Label=Reach \
		-o APT::FTPArchive::Release::Architectures=amd64 \
		-o APT::FTPArchive::Release::Description="Reach: SSH, remote desktop and DevOps" \
		release . > Release
	sign --clearsign --output InRelease Release
	sign --armor --detach-sign --output Release.gpg Release
	rm -f ./*.deb
)

# ---- DNF ------------------------------------------------------------------
rpm=$(ls "$pkgs"/*.rpm | head -1)
cp "$rpm" "$out/rpm/"
(
	cd "$out/rpm"
	createrepo_c --quiet --location-prefix "$base/" .
	sign --armor --detach-sign --output repodata/repomd.xml.asc repodata/repomd.xml
	rm -f ./*.rpm
)

gpg --batch --armor --export "$fpr" > "$out/reach-packages.asc"
echo "Signed with $fpr"
