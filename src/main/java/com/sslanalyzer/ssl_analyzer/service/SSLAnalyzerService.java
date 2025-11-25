package com.sslanalyzer.ssl_analyzer.service;

import com.sslanalyzer.ssl_analyzer.model.SSLResult;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SSLAnalyzerService {

    public SSLResult analyze(String hostname) {
        SSLResult result = new SSLResult();

        try {
            if (!hostname.startsWith("https://") && !hostname.startsWith("http://")) {
                hostname = "https://" + hostname;
            }

            URL url = new URL(hostname);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();

            String protocol = conn.getCipherSuite().contains("TLS") ? conn.getCipherSuite().split("_")[0] : conn.getCipherSuite();
            result.setProtocol(conn.getCipherSuite());

            Certificate[] certs = conn.getServerCertificates();
            X509Certificate cert = (X509Certificate) certs[0];

            String subjectDN = cert.getSubjectX500Principal().getName();
            String issuerDN = cert.getIssuerX500Principal().getName();

            LocalDate validFrom = cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            LocalDate validUntil = cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            long daysRemaining = ChronoUnit.DAYS.between(LocalDate.now(), validUntil);

            result.setCommonName(getAttribute(subjectDN, "CN"));

            String org = getAttribute(subjectDN, "O");
            if (org == null || org.isBlank()) {
                org = "Unknown Organization"; // Fallback only if missing
            }
            result.setOrganization(org);

            result.setSerialNumber(cert.getSerialNumber().toString(16).toUpperCase());
            result.setValidFrom(validFrom.toString());
            result.setValidUntil(validUntil.toString());

            result.setIssuerName(getAttribute(issuerDN, "CN"));
            result.setIssuerOrganization(getAttribute(issuerDN, "O"));

            boolean selfSigned = subjectDN.equals(issuerDN);
            result.setSelfSigned(selfSigned ? "Yes" : "No");

            result.setCipherSuite(conn.getCipherSuite());

            boolean weak = isWeakCipher(conn.getCipherSuite());
            result.setWeakCipher(weak ? "Yes" : "No");

            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            if (altNames != null) {
                String sans = altNames.stream()
                        .filter(e -> e.size() > 1)
                        .map(e -> e.get(1).toString())
                        .collect(Collectors.joining(", "));
                result.setSans(sans);
            } else {
                result.setSans("N/A");
            }

            result.setDaysRemaining((int) daysRemaining);

            String grade = computeGrade(daysRemaining, weak, selfSigned);
            result.setSecurityGrade(grade);

            int score = computeScore(grade);
            result.setSecurityScore(score);

            result.setCertificateStatus(daysRemaining < 0 ? "Expired" : "Valid");

        } catch (Exception e) {
            result.setCertificateStatus("Error");
            result.setSecurityGrade("F");
            result.setSecurityScore(0);
            result.setDaysRemaining(0);
            result.setProtocol("N/A");
            result.setCommonName("N/A");
            result.setOrganization("Unknown Organization"); // ✅ fallback text
            result.setSerialNumber("N/A");
            result.setValidFrom("N/A");
            result.setValidUntil("N/A");
            result.setIssuerName("N/A");
            result.setIssuerOrganization("N/A");
            result.setSelfSigned("N/A");
            result.setCipherSuite("N/A");
            result.setWeakCipher("N/A");
            result.setSans("N/A");
        }

        return result;
    }

    private String getAttribute(String dn, String key) {
        for (String part : dn.split(",")) {
            if (part.trim().startsWith(key + "=")) {
                return part.trim().substring((key + "=").length());
            }
        }
        return "";
    }

    private boolean isWeakCipher(String cipher) {
        String up = cipher.toUpperCase();
        return up.contains("RC4") || up.contains("DES") || up.contains("NULL") || up.contains("EXPORT") || up.contains("MD5");
    }

    private String computeGrade(long days, boolean weakCipher, boolean selfSigned) {
        if (selfSigned) return "C";
        if (weakCipher) return "B";
        if (days < 10) return "D";
        if (days < 30) return "C";
        if (days < 90) return "B";
        return "A+";
    }

    private int computeScore(String grade) {
        return switch (grade) {
            case "A+" -> 95;
            case "A" -> 88;
            case "B" -> 75;
            case "C" -> 65;
            default -> 50;
        };
    }
}
