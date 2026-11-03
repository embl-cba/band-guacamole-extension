# BAND Guacamole extension

Authentication extension for [Apache Guacamole](https://guacamole.apache.org/)
1.6.0, as used by the BAND portal. Apache License 2.0.

Based on the Guacamole extension of Strudel Web, developed by the
[MASSIVE](https://www.massive.org.au/) facility at Monash University
(Australia).

The portal does the login (Keycloak). When a user opens a desktop or a
terminal, the portal puts that one connection in a short-lived cookie
(1 minute, path `/`) and loads Guacamole in an iframe; this extension turns
the cookie into the Guacamole connection:

| cookie | connection |
|---|---|
| `vnc-credentials-strudel-web` | VNC to the portal's own SSH tunnel to the desktop (`localhost:<port>`), with SFTP to the desktop node for file transfer |
| `ssh-credentials-strudel-web` | SSH to the desktop node, port 22 |

Both cookies are URL-encoded JSON (`name`, `protocol`, `hostname`, `port`,
`username`, `privateKey`, and for VNC `password` and `remotehost`; SSH may
have `command`).

## The cookie is untrusted

Guacamole has no login of its own here: whoever can reach `/guacamole/` can
send any cookie. So the extension only accepts what the portal itself does:

- protocol `vnc` in the VNC cookie and `ssh` in the SSH cookie, nothing else;
- VNC only to `localhost`, port 1024-65535;
- SSH (and SFTP) only to the hosts in `band-ssh-hosts`, SSH only to port 22;
- a plain username (`/home/<username>` is the SFTP root).

Anything else is refused and logged with the reason and the client address,
never with the cookie's content. The VNC password and the user's key still
protect each desktop: the extension only limits where Guacamole may connect.

## Configuration

`GUACAMOLE_HOME/guacamole.properties`:

    # the desktop nodes, as the portal's execHost gives them (comma separated)
    band-ssh-hosts: 192.168.0.11, 192.168.0.12

Without it every connection is refused.

## Build and install

    mvn package        # JDK 11; gives target/band-guacamole-extension-<version>.jar

- the jar goes to `GUACAMOLE_HOME/extensions/`;
- [gson](https://github.com/google/gson) 2.14.0 goes to `GUACAMOLE_HOME/lib/`
  (the Guacamole web application does not include it);
- restart Tomcat.

The BAND deployment ([embl-cba/band](https://github.com/embl-cba/band), role
`eosc_vd_portal`) installs the jar from this repository's release and gson
from Maven Central, both checked by sha256.

## History

1.6.1: the cookie is checked (see above); a separate connection per cookie
(1.6.0 shared one, so a desktop and a terminal opened within the same minute
mixed their settings); gson 2.4 → 2.14.0; the jar no longer bundles the
Guacamole and servlet libraries (it never used them); renamed from
`massive-guacamole-remote` (package `org.embl.band.guacamole.auth`).

1.6.0 and earlier: `massive-guacamole-remote`, from MASSIVE's Strudel Web
(Monash University), ported to Guacamole 1.x at EMBL.
