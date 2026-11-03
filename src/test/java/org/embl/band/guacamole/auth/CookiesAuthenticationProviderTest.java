package org.embl.band.guacamole.auth;

import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.junit.jupiter.api.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CookiesAuthenticationProviderTest {

    private static final String NODE = "192.168.0.11";
    private final CookiesAuthenticationProvider provider =
            new CookiesAuthenticationProvider(List.of(NODE, "192.168.0.12"));

    // what band-portal-web (and eosc-js) put in the cookies
    private static final String VNC = "{\"name\":\"desktop1\",\"hostname\":\"localhost\",\"port\":\"43337\","
            + "\"password\":\"otp12345\",\"protocol\":\"vnc\",\"username\":\"yi.sun_embl\","
            + "\"remotehost\":\"" + NODE + "\",\"privateKey\":\"KEY\"}";
    private static final String SSH = "{\"name\":\"desktop2\",\"username\":\"yi.sun_embl\","
            + "\"hostname\":\"" + NODE + "\",\"port\":\"22\",\"privateKey\":\"KEY\",\"protocol\":\"ssh\"}";

    private Map<String, GuacamoleConfiguration> connect(String... nameValue) {
        Cookie[] cookies = new Cookie[nameValue.length / 2];
        for (int i = 0; i < cookies.length; i++)
            cookies[i] = new Cookie(nameValue[2 * i],
                    URLEncoder.encode(nameValue[2 * i + 1], StandardCharsets.UTF_8));
        HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getCookies": return cookies;
                        case "getRemoteAddr": return "203.0.113.5";
                        case "getHeaderNames":
                        case "getParameterNames":
                        case "getHeaders": return Collections.emptyEnumeration();
                        case "getParameterMap": return Collections.emptyMap();
                        default: return null;
                    }
                });
        return provider.getAuthorizedConfigurations(new Credentials(null, null, request));
    }

    private static String with(String json, String key, String value) {
        return json.replaceFirst("\"" + key + "\":\"[^\"]*\"", "\"" + key + "\":" + value);
    }

    @Test
    void desktop() {
        GuacamoleConfiguration c = connect("vnc-credentials-strudel-web", VNC).get("desktop1");
        assertEquals("vnc", c.getProtocol());
        assertEquals("localhost", c.getParameter("hostname"));
        assertEquals("43337", c.getParameter("port"));
        assertEquals("otp12345", c.getParameter("password"));
        assertEquals(NODE, c.getParameter("sftp-hostname"));
        assertEquals("/home/yi.sun_embl", c.getParameter("sftp-root-directory"));
    }

    @Test
    void terminal() {
        GuacamoleConfiguration c = connect("ssh-credentials-strudel-web", SSH).get("desktop2");
        assertEquals("ssh", c.getProtocol());
        assertEquals(NODE, c.getParameter("hostname"));
        assertEquals("22", c.getParameter("port"));
        assertEquals("yi.sun_embl", c.getParameter("username"));
        assertEquals(null, c.getParameter("password"));
    }

    @Test
    void bothCookiesGiveSeparateConnections() {
        Map<String, GuacamoleConfiguration> m = connect("vnc-credentials-strudel-web", VNC,
                                                        "ssh-credentials-strudel-web", SSH);
        assertEquals(2, m.size());
        assertNotSame(m.get("desktop1"), m.get("desktop2"));
        assertEquals("vnc", m.get("desktop1").getProtocol());
        assertEquals("localhost", m.get("desktop1").getParameter("hostname"));
        assertEquals("ssh", m.get("desktop2").getProtocol());
    }

    @Test
    void eoscJsTerminalWithCommand() {
        String json = SSH.replace("{", "{\"command\":\"bash\",");
        assertEquals("bash", connect("ssh-credentials-strudel-web", json).get("desktop2").getParameter("command"));
    }

    @Test
    void otherProtocolsAreRefused() {
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "protocol", "\"telnet\"")).isEmpty());
        assertTrue(connect("ssh-credentials-strudel-web", with(SSH, "protocol", "\"telnet\"")).isEmpty());
        assertTrue(connect("ssh-credentials-strudel-web", with(SSH, "protocol", "\"rdp\"")).isEmpty());
        // a VNC cookie can't ask for SSH and the other way round
        assertTrue(connect("vnc-credentials-strudel-web", SSH).isEmpty());
        assertTrue(connect("ssh-credentials-strudel-web", VNC).isEmpty());
    }

    @Test
    void otherHostsAreRefused() {
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "hostname", "\"192.168.0.99\"")).isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "remotehost", "\"192.168.0.99\"")).isEmpty());
        assertTrue(connect("ssh-credentials-strudel-web", with(SSH, "hostname", "\"192.168.0.99\"")).isEmpty());
        assertTrue(connect("ssh-credentials-strudel-web", with(SSH, "hostname", "\"localhost\"")).isEmpty());
    }

    @Test
    void badPortsAreRefused() {
        assertTrue(connect("ssh-credentials-strudel-web", with(SSH, "port", "\"2222\"")).isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "port", "\"22\"")).isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "port", "\"99999\"")).isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "port", "\"5901 \"")).isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "port", "43337")).isEmpty());   // a number
    }

    @Test
    void badUsernamesAreRefused() {
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "username", "\"../root\"")).isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "username", "\"a/b\"")).isEmpty());
        assertTrue(connect("ssh-credentials-strudel-web", with(SSH, "username", "\"\"")).isEmpty());
    }

    @Test
    void brokenCookiesAreRefused() {
        assertTrue(connect("vnc-credentials-strudel-web", "not json").isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", "null").isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", "[1,2]").isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", "{}").isEmpty());
        assertTrue(connect("vnc-credentials-strudel-web", with(VNC, "password", "{\"a\":1}")).isEmpty());
        // a broken cookie doesn't stop a good one
        assertEquals(1, connect("vnc-credentials-x", "{", "ssh-credentials-strudel-web", SSH).size());
    }

    @Test
    void otherCookiesAreIgnored() {
        assertTrue(connect("JSESSIONID", "abc").isEmpty());
    }

    @Test
    void nothingAllowedWithoutSshHosts() {
        CookiesAuthenticationProvider none = new CookiesAuthenticationProvider(List.of());
        assertFalse(provider.getIdentifier().isEmpty());
        // same cookie as desktop(), but no desktop node is known
        HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> method.getName().equals("getCookies")
                        ? new Cookie[]{new Cookie("vnc-credentials-strudel-web",
                                URLEncoder.encode(VNC, StandardCharsets.UTF_8))}
                        : method.getReturnType() == java.util.Enumeration.class ? Collections.emptyEnumeration() : null);
        assertTrue(none.getAuthorizedConfigurations(new Credentials(null, null, request)).isEmpty());
    }
}
