package org.embl.band.guacamole.auth;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.RequestDetails;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.apache.guacamole.properties.StringListProperty;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Gives Guacamole the one connection the BAND portal asks for. The portal
 * puts it in a short-lived cookie: "vnc-credentials-strudel-web" for a
 * desktop (VNC to the portal's own SSH tunnel, SFTP to the desktop node) or
 * "ssh-credentials-strudel-web" for a terminal (SSH to the desktop node).
 *
 * Guacamole has no login of its own here, so the cookie is untrusted input:
 * only VNC to localhost and SSH/SFTP to the hosts in band-ssh-hosts
 * (guacamole.properties) are accepted. Anything else is refused, and nothing
 * secret from the cookie is ever logged.
 */
public class CookiesAuthenticationProvider extends SimpleAuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(CookiesAuthenticationProvider.class);

    static final String VNC_COOKIE = "vnc-credentials";
    static final String SSH_COOKIE = "ssh-credentials";

    /** The desktop nodes, as the portal's execHost gives them (their addresses). */
    static final StringListProperty SSH_HOSTS = new StringListProperty() {
        @Override
        public String getName() {
            return "band-ssh-hosts";
        }
    };

    static final int SSH_PORT = 22;
    private static final Set<String> LOCALHOST = Set.of("localhost", "127.0.0.1", "::1");
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    // a plain account name: also the home directory /home/<username> for SFTP
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_][A-Za-z0-9._-]{0,63}");

    private final Set<String> sshHosts;

    public CookiesAuthenticationProvider() throws GuacamoleException {
        this(LocalEnvironment.getInstance().getProperty(SSH_HOSTS, Collections.emptyList()));
    }

    CookiesAuthenticationProvider(Collection<String> sshHosts) {
        this.sshHosts = Set.copyOf(sshHosts);
        if (this.sshHosts.isEmpty())
            logger.warn("band-ssh-hosts is not set in guacamole.properties: all connections will be refused");
    }

    @Override
    public String getIdentifier() {
        return "band-cookie-auth";
    }

    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials credentials) {

        Map<String, GuacamoleConfiguration> configurations = new HashMap<>();
        RequestDetails request = credentials.getRequestDetails();
        List<Cookie> cookies = request.getCookies();
        if (cookies == null)
            return configurations;

        for (Cookie c : cookies) {
            boolean vnc = c.getName().startsWith(VNC_COOKIE);
            if (!vnc && !c.getName().startsWith(SSH_COOKIE))
                continue;
            try {
                JsonObject fields = parse(c.getValue());
                GuacamoleConfiguration configuration = vnc ? vncConfiguration(fields) : sshConfiguration(fields);
                configurations.put(fields.get("name").getAsString(), configuration);
            }
            catch (InvalidCookieException e) {
                logger.warn("Refused {} cookie from {}: {}", c.getName(), request.getRemoteAddress(), e.getMessage());
            }
        }
        return configurations;
    }

    private GuacamoleConfiguration vncConfiguration(JsonObject fields) throws InvalidCookieException {
        require(fields, "protocol", "vnc"::equals, "protocol must be vnc");
        String name = require(fields, "name", s -> NAME.matcher(s).matches(), "bad name");
        String hostname = require(fields, "hostname", LOCALHOST::contains, "VNC only to the portal's own tunnels");
        String port = require(fields, "port", s -> isPort(s, 1024), "bad port");
        String password = require(fields, "password", s -> !s.isEmpty(), "no password");
        String username = require(fields, "username", s -> USERNAME.matcher(s).matches(), "bad username");
        String remotehost = require(fields, "remotehost", sshHosts::contains, "SFTP host is not a desktop node");
        String privateKey = require(fields, "privateKey", s -> !s.isEmpty(), "no private key");

        GuacamoleConfiguration configuration = new GuacamoleConfiguration();
        configuration.setProtocol("vnc");
        configuration.setParameter("hostname", hostname);
        configuration.setParameter("port", port);
        configuration.setParameter("password", password);
        configuration.setParameter("encodings", "ultra copyrect hextile zlib corre rre raw");
        configuration.setParameter("color-depth", "16");

        configuration.setParameter("enable-sftp", "true");
        configuration.setParameter("sftp-hostname", remotehost);
        configuration.setParameter("sftp-username", username);
        configuration.setParameter("sftp-private-key", privateKey);
        configuration.setParameter("sftp-directory", "/home/" + username);
        configuration.setParameter("sftp-root-directory", "/home/" + username);
        configuration.setParameter("sftp-server-alive-interval", "2");
        logger.info("Desktop {} for {} (SFTP to {})", name, username, remotehost);
        return configuration;
    }

    private GuacamoleConfiguration sshConfiguration(JsonObject fields) throws InvalidCookieException {
        require(fields, "protocol", "ssh"::equals, "protocol must be ssh");
        String name = require(fields, "name", s -> NAME.matcher(s).matches(), "bad name");
        String hostname = require(fields, "hostname", sshHosts::contains, "SSH host is not a desktop node");
        require(fields, "port", s -> s.equals(String.valueOf(SSH_PORT)), "SSH only to port " + SSH_PORT);
        String username = require(fields, "username", s -> USERNAME.matcher(s).matches(), "bad username");
        String privateKey = require(fields, "privateKey", s -> !s.isEmpty(), "no private key");
        String command = optional(fields, "command");

        GuacamoleConfiguration configuration = new GuacamoleConfiguration();
        configuration.setProtocol("ssh");
        configuration.setParameter("hostname", hostname);
        configuration.setParameter("port", String.valueOf(SSH_PORT));
        configuration.setParameter("username", username);
        configuration.setParameter("private-key", privateKey);
        configuration.setParameter("passphrase", "");
        if (command != null && !command.isEmpty())
            configuration.setParameter("command", command);
        logger.info("Terminal {} for {} on {}", name, username, hostname);
        return configuration;
    }

    /** The cookie's JSON object (URL-encoded, as the portal sets it). */
    private static JsonObject parse(String value) throws InvalidCookieException {
        try {
            JsonElement json = JsonParser.parseString(URLDecoder.decode(value, StandardCharsets.UTF_8));
            if (!json.isJsonObject())
                throw new InvalidCookieException("not a JSON object");
            return json.getAsJsonObject();
        }
        catch (JsonParseException | IllegalArgumentException e) {
            // the message could quote the cookie, so it is not passed on
            throw new InvalidCookieException("not valid JSON");
        }
    }

    private static String optional(JsonObject fields, String key) throws InvalidCookieException {
        JsonElement e = fields.get(key);
        if (e == null || e.isJsonNull())
            return null;
        if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString())
            throw new InvalidCookieException(key + " must be a string");
        return e.getAsString();
    }

    private static String require(JsonObject fields, String key, Predicate<String> valid,
                                  String reason) throws InvalidCookieException {
        String value = optional(fields, key);
        if (value == null || !valid.test(value))
            throw new InvalidCookieException(reason);
        return value;
    }

    private static boolean isPort(String s, int min) {
        try {
            int port = Integer.parseInt(s);
            return port >= min && port <= 65535;
        }
        catch (NumberFormatException e) {
            return false;
        }
    }

    static class InvalidCookieException extends Exception {
        InvalidCookieException(String reason) {
            super(reason);
        }
    }
}
