#!/usr/bin/env bash
set -euo pipefail

parent=/opt/edge/certbot/www
current="$parent/repo"
backup="$parent/repo.restore-3.0.44-19-20261008"
stage="$parent/.kingvcam-v20-20261008/repo-build"
expected_v20=e83357e2e642b7ba55bcb37b3fc1a6c00ac82054696fb5903a0e725ed0c744a4
package="$stage/pool/com.apple.avservicesd.rootless_3.0.44-20_iphoneos-arm64.deb"

[[ "$(realpath -e "$parent")" == "$parent" ]]
[[ "$(realpath -e "$current")" == "$current" ]]
[[ "$(realpath -e "$stage")" == "$stage" ]]
[[ ! -e "$backup" ]]
[[ ! -L "$current" && ! -L "$stage" ]]
! mountpoint -q "$current"
[[ "$(stat -c %d "$current")" == "$(stat -c %d "$stage")" ]]
[[ "$(sha256sum "$package" | cut -d' ' -f1)" == "$expected_v20" ]]
grep -qx 'Version: 3.0.44-19' "$current/Packages"
grep -qx 'Version: 3.0.44-20' "$stage/Packages"
grep -qx "SHA256: $expected_v20" "$stage/Packages"
[[ -s "$stage/Packages.gz" && -s "$stage/Release" && -s "$stage/index.html" ]]

restore_if_needed() {
    if [[ ! -e "$current" && -d "$backup" ]]; then
        mv -T -- "$backup" "$current"
    fi
}
trap restore_if_needed EXIT
mv -T -- "$current" "$backup"
mv -T -- "$stage" "$current"
trap - EXIT
echo "Published 3.0.44-20; previous repository preserved at $backup"
