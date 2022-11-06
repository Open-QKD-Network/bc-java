package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.logging.Logger;
import java.lang.System;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.NamedGroup;

import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;

public class JceTlsECDHPQC
    implements TlsAgreement
{
    static final Logger LOG = Logger.getLogger(JceTlsECDHPQC.class.getName());

    protected final JceTlsECDH ecdhAgreement;
    protected int namedGroup;
    // POC related
    protected PQCAgreement pqcAgreement;

    public JceTlsECDHPQC(TlsAgreement ecdhAgreement, int namedGroup,  boolean client)
    {
        this.ecdhAgreement = (JceTlsECDH) ecdhAgreement;
        this.namedGroup = namedGroup;
        createPQCAgreement(client);
    }

    public byte[] generateEphemeral() throws IOException
    {
        byte[] ecdh = this.ecdhAgreement.generateEphemeral();
        byte[] pqc = this.pqcAgreement.generateEphemeral();
        byte[] ret = new byte[ecdh.length + pqc.length];
        LOG.info("JceTlsECDHPQC.generateEphemeral, ecdh length:" + ecdh.length + ", pqc length:" + pqc.length);
        System.arraycopy(ecdh, 0, ret, 0, ecdh.length);
        System.arraycopy(pqc, 0, ret, ecdh.length, pqc.length);
        return ret;
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        LOG.info("JceTlsECDHPQC.receivePeerValue, length:" + peerValue.length);
        if (pqcAgreement.role == PQCAgreement.Role.CLIENT)
        {
        }
        else
        {
            if (this.namedGroup == NamedGroup.p256_frodo640aes)
            {
                byte[] ecdh = new byte[65];
                System.arraycopy(peerValue, 0, ecdh, 0, 65);
                byte[] pqc = new byte[9616]; // Frodo640AES public key size 9616
                System.arraycopy(peerValue, 65, pqc, 0, 9616);
                this.ecdhAgreement.receivePeerValue(ecdh);
                this.pqcAgreement.receivePeerValue(pqc);
            }
        }
    }

    public TlsSecret calculateSecret() throws IOException
    {
        if (pqcAgreement.role == PQCAgreement.Role.CLIENT)
        {
            return null;
        }
        else
        {
            if (this.namedGroup == NamedGroup.p256_frodo640aes)
            {
                TlsSecret ecdh = this.ecdhAgreement.calculateSecret();
                TlsSecret pqc = this.pqcAgreement.calculateSecret();
                byte[] ecdh_key = ((org.bouncycastle.tls.crypto.impl.AbstractTlsSecret) ecdh).copyData();
                byte[] pqc_key  = ((org.bouncycastle.tls.crypto.impl.AbstractTlsSecret) pqc).copyData();
                byte[] hybrid_key = new byte[ecdh_key.length + pqc_key.length];
                System.arraycopy(ecdh_key, 0, hybrid_key, 0, ecdh_key.length);
                System.arraycopy(pqc_key, 0, hybrid_key, ecdh_key.length, pqc_key.length);
                LOG.info("JceTlsECDHPQC.calculateSecret, ecdh_key length:" + ecdh_key.length + ", pqc_key length:" + pqc_key.length);
                return this.ecdhAgreement.domain.crypto.adoptLocalSecret(hybrid_key);
            }
            return null;
        }
    }

    private void createPQCAgreement(boolean client)
    {
        if (client)
        {
            if (this.namedGroup == NamedGroup.p256_frodo640aes)
            {
                pqcAgreement = new PQCAgreement(FrodoParameterSpec.frodokem19888r3, PQCAgreement.Role.CLIENT);
            }
        }
        else
        {
            if (this.namedGroup == NamedGroup.p256_frodo640aes)
            {
                pqcAgreement = new PQCAgreement(FrodoParameterSpec.frodokem19888r3, PQCAgreement.Role.SERVER);
            }
        }
    }
}
