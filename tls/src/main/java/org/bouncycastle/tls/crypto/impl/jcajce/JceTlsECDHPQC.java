package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

public class JceTlsECDHPQC
    implements TlsAgreement
{
    protected final JceTlsECDH ecdhAgreement;
    protected int namedGroup;
    // POC related

    public JceTlsECDHPQC(TlsAgreement ecdhAgreement, int namedGroup)
    {
        this.ecdhAgreement = (JceTlsECDH) ecdhAgreement;
	this.namedGroup = namedGroup;
    }

    public byte[] generateEphemeral() throws IOException
    {
        return this.ecdhAgreement.generateEphemeral();
        // POC
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.ecdhAgreement.receivePeerValue(peerValue);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        return this.ecdhAgreement.calculateSecret();
    }
}
