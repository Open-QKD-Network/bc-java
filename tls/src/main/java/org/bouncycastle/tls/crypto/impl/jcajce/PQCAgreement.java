package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.Security;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;
import javax.crypto.KeyGenerator;
import java.util.logging.Logger;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.jcajce.provider.frodo.BCFrodoPublicKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;

public class PQCAgreement
    implements TlsAgreement
{
    static final Logger LOG = Logger.getLogger(PQCAgreement.class.getName());

    public enum Role {
        CLIENT,
	SERVER
    }

    protected Role role;
    protected KeyPair localKeyPair;
    protected byte[] peerData;
    protected byte[] sharedSecret;
    protected AlgorithmParameterSpec algorithmParameterSpec;

    public PQCAgreement(AlgorithmParameterSpec spec, Role role)
    {
        this.algorithmParameterSpec = spec;
        this.role = role;
        initialize();
    }

    public byte[] generateEphemeral() throws IOException
    {
        if (role == Role.CLIENT)
        {
            // return public key
            if (algorithmParameterSpec instanceof FrodoParameterSpec)
            {
                byte[] rawKey = ((FrodoPublicKeyParameters) PublicKeyFactory.createKey(
                    localKeyPair.getPublic().getEncoded())).getPublicKey();
                return rawKey;
            }
            else
            {
                return null;
            }
        }
        else
        {
            try
            {
                // calculate shared secret and return cipher text
                if (algorithmParameterSpec instanceof FrodoParameterSpec)
                {
                    FrodoPublicKeyParameters fpkp = new FrodoPublicKeyParameters(FrodoParameters.frodokem19888r3, peerData);
                    PublicKey pk = new BCFrodoPublicKey(fpkp);

                    KeyGenerator keyGen = KeyGenerator.getInstance("Frodo", "BCPQC");
                    keyGen.init(new KEMGenerateSpec(pk, "AES"), new SecureRandom());
                    SecretKeyWithEncapsulation secEnc = (SecretKeyWithEncapsulation) keyGen.generateKey();
                    this.sharedSecret = secEnc.getEncoded();
                    byte[] ct = secEnc.getEncapsulation();
                    LOG.info("PQCAgreement.generateEphemeral, cipher text length:" + ct.length + ",shared key length:" + sharedSecret.length);
                    return ct;
                }
            }
            catch (NoSuchAlgorithmException e)
            {
                LOG.info("PQCAgreement.generateEphemeral, NoSuchAlgorithmException:" + e);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                LOG.info("PQCAgreement.generateEphemeral, InvalidAlgorithmParameterException:" + e);
            }
            catch (NoSuchProviderException e)
            {
                LOG.info("PQCAgreement.generateEphemeral, NoSuchProviderException:" + e);
            }
            return null;
        }
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.peerData = peerValue.clone();
    }

    public TlsSecret calculateSecret() throws IOException
    {
        try
        {
            if (role == Role.SERVER)
            {
                if (algorithmParameterSpec instanceof FrodoParameterSpec)
                {
                    return new JceTlsSecret(null, this.sharedSecret);
                }
            }
            else
            {
                if (algorithmParameterSpec instanceof FrodoParameterSpec)
                {
                    // calculate the shared secret
                    KeyGenerator keyGen = KeyGenerator.getInstance("Frodo", "BCPQC");
                    keyGen.init(new KEMExtractSpec(this.localKeyPair.getPrivate(), this.peerData, "AES"));
                    SecretKeyWithEncapsulation enc = (SecretKeyWithEncapsulation) keyGen.generateKey();
                    this.sharedSecret = enc.getEncoded();
                    return new JceTlsSecret(null, this.sharedSecret);
                }
            }
        }
        catch (Exception e)
        {
            LOG.info("PQCAgreement.calculateSecret, throws exception:" + e);
        }
        return null;
    }

    private void initialize()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        if (this.role == Role.SERVER)
        {
            // For server, we do not need to generate keypair.
            return;
        }
        try
        {
            if (algorithmParameterSpec instanceof FrodoParameterSpec)
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Frodo", "BCPQC");
                kpg.initialize(this.algorithmParameterSpec, new SecureRandom());
                this.localKeyPair = kpg.generateKeyPair();
	    }
        }
        catch (Exception e)
        {
            LOG.info("PQCAgreement.initialize, throws exception:" + e);
        }
    }
}
