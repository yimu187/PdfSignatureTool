package com.pdftool.signature.process;

import org.apache.pdfbox.examples.signature.CreateSignature;
import org.apache.pdfbox.examples.signature.TSAClient;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;

public class CreatePDFSignature extends CreateSignature {

    private String name;
    private String location;
    private String reason;

    /**
     * Initialize the signature creator with a keystore and certficate password.
     *
     * @param keystore the keystore containing the signing certificate
     * @param password the password for recovering the key
     * @param name the name for signature
     * @param location the location for signature
     * @param reason the reason for signature
     * @throws KeyStoreException         if the keystore has not been initialized (loaded)
     * @throws NoSuchAlgorithmException  if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the given password is wrong
     */
    public CreatePDFSignature(KeyStore keystore, char[] password, String name, String location, String reason) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
        super(keystore, password);
        this.name = name;
        this.location = location;
        this.reason = reason;
    }

    public void signDetached(PDDocument document, OutputStream output, TSAClient tsaClient)
            throws IOException {

        // create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName(name);
        signature.setLocation(location);
        signature.setReason(reason);

        // the signing date, needed for valid signature
        signature.setSignDate(Calendar.getInstance());

        // register signature dictionary and sign interface
        document.addSignature(signature, this);

        // write incremental (only for signing purpose)
        document.saveIncremental(output);
    }

    /**
     * Signs the given PDF file.
     * @param ins InputStream PDF file
     * @param outs OutputStream
     * @param tsaClient optional TSA client
     * @throws IOException if the input file could not be read
     */
    public void signDetached(InputStream ins, OutputStream outs, TSAClient tsaClient) throws IOException
    {
        if (ins == null)
        {
            throw new FileNotFoundException("Document for signing does not exist");
        }

        // sign
        PDDocument doc = PDDocument.load(ins);
        signDetached(doc, outs, tsaClient);
        doc.close();
    }
}
