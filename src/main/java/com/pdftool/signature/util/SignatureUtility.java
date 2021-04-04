package com.pdftool.signature.util;

import com.pdftool.signature.dto.SignatureDataDto;
import com.pdftool.signature.process.CreatePDFSignature;
import com.pdftool.signature.process.ShowPDFSignatures;
import org.apache.commons.io.FileUtils;
import org.apache.pdfbox.examples.signature.validation.AddValidationInformation;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.springframework.util.Assert;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

public class SignatureUtility {

    public static void getPdfContent(String pdfPath) throws IOException, CertificateException {

        byte[] bytes = FileUtils.readFileToByteArray(new File(pdfPath));

        List<SignatureDataDto> extractedData = extractSignatures(null, bytes);
        String contentHash = !extractedData.isEmpty() ? extractedData.get(0).getContentHash() : null;

        Assert.notNull(contentHash,"Content null");
    }

    public static File sign(String p12KeyStorePassword, byte[] p12KeyStorePath, byte[] fileToBeSignedContent, String fileToBeSignedPath) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException, CertificateException {

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        char[] password = p12KeyStorePassword.toCharArray();
        InputStream isp12KeyStore = new ByteArrayInputStream(p12KeyStorePath);
        keystore.load(isp12KeyStore, password);

        // sign PDF
        CreatePDFSignature signing = new CreatePDFSignature(keystore, password, "MURAT YILMAZ", "ISTANBUL", "TESTING");

        InputStream insDataToBeSigned = new ByteArrayInputStream(fileToBeSignedContent);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        signing.signDetached(insDataToBeSigned, bos, null);
        byte[] bytes = bos.toByteArray();

        File inFile = new File(fileToBeSignedPath);
        String name = inFile.getName();
        String substring = name.substring(0, name.lastIndexOf('.'));
        File outFileSigned = new File(inFile.getParent(), substring + "_signed.pdf");
        outFileSigned.createNewFile();
        System.out.println("signed path => " + outFileSigned.getPath());
        FileUtils.writeByteArrayToFile(outFileSigned, bytes);

        Security.addProvider(SecurityProvider.getProvider());

        // add ocspInformation
        AddValidationInformation addOcspInformation = new AddValidationInformation();

        File outFile_ocsp = new File(inFile.getParent(), substring + "_ocsp.pdf");
        outFile_ocsp.createNewFile();
        System.out.println("ocsp path => " + outFile_ocsp.getPath());
        addOcspInformation.validateSignature(outFileSigned, outFile_ocsp);
        return outFile_ocsp;
    }

    public static List<SignatureDataDto> extractSignatures(String encPass, byte[] signedPDFContent) throws IOException, CertificateException {
        ShowPDFSignatures showPDFSignatures = new ShowPDFSignatures();
        List<SignatureDataDto> signatureDataDtos = showPDFSignatures.extractSignatures(encPass, signedPDFContent);
        return signatureDataDtos;

    }

}
