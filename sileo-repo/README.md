# KingVCam Sileo source

Flat APT repository URL: `https://kingvcam.com/repo/`

The repository contains the owner-confirmed 3.0.44-20 rootless package. Its
exact SHA-256 is pinned in `build_repo.py`; experimental builds must not be
published by changing a filename alone. The 3.0.44-19 package remains in the
server restore snapshot and Git tag `v3.0.44-19`; 3.0.44-14 has a separate
restore snapshot and Git tag.

The public files are served by the shared edge Nginx from
`/opt/edge/certbot/www/repo`, independently of the KingVCam API. Updating
indexes never changes login or the camera engine. To regenerate on the server:

```sh
python3 build_repo.py /path/to/official.deb /path/to/staging-repo
```

Check `Packages`, `Packages.gz`, `Release`, the `.deb` SHA-256, and public HTTP
responses before pointing Sileo to the source. Confirm reboot/jailbreak
behavior on the test iPhone before publishing to all users.
