package rotasaude.signer.engine;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.util.function.Function;

/**
 * Para onde o signer aceita ir buscar LCR. Só http/https. Em produção, nenhum destino
 * interno: o ponto de distribuição vem do certificado, e um certificado de terceiro não pode
 * fazer o signer sondar a rede interna (SSRF). Em dev e staging a AC de teste mora em localhost.
 */
public final class CrlUrlPolicy {

    private final boolean production;
    private final Function<String, InetAddress[]> resolver;

    public CrlUrlPolicy(boolean production, Function<String, InetAddress[]> resolver) {
        this.production = production;
        this.resolver = resolver;
    }

    /** Resolução real de nomes; erro vira lista vazia (recusada). */
    public static InetAddress[] resolve(String host) {
        try {
            return InetAddress.getAllByName(host);
        } catch (Exception e) {
            return new InetAddress[0];
        }
    }

    public boolean allowed(String url) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) return false;
            String host = uri.getHost();
            if (host == null || host.isBlank()) return false;
            if (!production) return true;
            InetAddress[] addresses = resolver.apply(host);
            if (addresses == null || addresses.length == 0) return false;
            for (InetAddress address : addresses) {
                if (internal(address)) return false;
            }
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean internal(InetAddress address) {
        if (address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isAnyLocalAddress() || address.isMulticastAddress()) return true;
        // IPv6 de uso local (fc00::/7), que o isSiteLocalAddress não cobre.
        return address instanceof Inet6Address && (address.getAddress()[0] & 0xfe) == 0xfc;
    }
}
