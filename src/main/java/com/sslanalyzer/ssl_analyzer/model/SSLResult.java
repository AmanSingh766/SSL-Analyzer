package com.sslanalyzer.ssl_analyzer.model;

public class SSLResult {
    private String securityGrade;
    private int daysRemaining;
    private String certificateStatus;
    private String protocol;
    private String commonName;
    private String organization;
    private String serialNumber;
    private String validFrom;
    private String validUntil;
    private String issuerName;
    private String issuerOrganization;
    private String selfSigned;
    private String cipherSuite;
    private String weakCipher;
    private String sans;
    private int securityScore;

    // Getters & setters for all fields

    public String getSecurityGrade() { return securityGrade; }
    public void setSecurityGrade(String securityGrade) { this.securityGrade = securityGrade; }

    public int getDaysRemaining() { return daysRemaining; }
    public void setDaysRemaining(int daysRemaining) { this.daysRemaining = daysRemaining; }

    public String getCertificateStatus() { return certificateStatus; }
    public void setCertificateStatus(String certificateStatus) { this.certificateStatus = certificateStatus; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public String getCommonName() { return commonName; }
    public void setCommonName(String commonName) { this.commonName = commonName; }

    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public String getValidFrom() { return validFrom; }
    public void setValidFrom(String validFrom) { this.validFrom = validFrom; }

    public String getValidUntil() { return validUntil; }
    public void setValidUntil(String validUntil) { this.validUntil = validUntil; }

    public String getIssuerName() { return issuerName; }
    public void setIssuerName(String issuerName) { this.issuerName = issuerName; }

    public String getIssuerOrganization() { return issuerOrganization; }
    public void setIssuerOrganization(String issuerOrganization) { this.issuerOrganization = issuerOrganization; }

    public String getSelfSigned() { return selfSigned; }
    public void setSelfSigned(String selfSigned) { this.selfSigned = selfSigned; }

    public String getCipherSuite() { return cipherSuite; }
    public void setCipherSuite(String cipherSuite) { this.cipherSuite = cipherSuite; }

    public String getWeakCipher() { return weakCipher; }
    public void setWeakCipher(String weakCipher) { this.weakCipher = weakCipher; }

    public String getSans() { return sans; }
    public void setSans(String sans) { this.sans = sans; }

    public int getSecurityScore() { return securityScore; }
    public void setSecurityScore(int securityScore) { this.securityScore = securityScore; }
}
