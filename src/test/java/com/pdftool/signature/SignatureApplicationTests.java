package com.pdftool.signature;

import com.pdftool.signature.util.SignatureUtility;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.util.Assert;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@SpringBootTest
class SignatureApplicationTests {

	@Autowired
	Environment environment;

	@Test
	void contextLoads() {
	}

	private File getSignedPdfContent(byte[] pdfContentToBeSigned, String pdfToBeSignedPath) throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
		String p12KeyStorePass = environment.getProperty("cert.p12.file.password");
		String p12KeyStorePath = this.getClass().getClassLoader().getResource("keystore.p12").getPath();
		byte[] p12KeyStoreContent = FileUtils.readFileToByteArray(new File(p12KeyStorePath));
		return SignatureUtility.sign(p12KeyStorePass, p12KeyStoreContent, pdfContentToBeSigned, pdfToBeSignedPath);
	}

	@Test
	void signatureTest() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
		String fileToBeSignedPath = this.getClass().getClassLoader().getResource("sample.pdf").getPath();
		byte[] pdfContent = FileUtils.readFileToByteArray(new File(fileToBeSignedPath));
		File signedPDFContent = getSignedPdfContent(pdfContent, fileToBeSignedPath);
		Assert.notNull(signedPDFContent, "No Content");
	}

	@Test
	void extractSignaturesTest() throws CertificateException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
		String fileToBeSignedPath = this.getClass().getClassLoader().getResource("sample.pdf").getPath();
		byte[] pdfContent = FileUtils.readFileToByteArray(new File(fileToBeSignedPath));
		File signedPDFContent = getSignedPdfContent(pdfContent, fileToBeSignedPath);
		byte[] bytes = FileUtils.readFileToByteArray(signedPDFContent);

//		List<SignatureDataDto> signatureDataDtos = SignatureUtility.extractSignatures(null, bytes);
//		Assert.notEmpty(signatureDataDtos, "List Empty");
//		Assert.isTrue(signatureDataDtos.size() == 1, "List size is not one");
//
//		File doubleSignedPDFFile = getSignedPdfContent(bytes, fileToBeSignedPath);
//		byte[] doubleSignPdfContent = FileUtils.readFileToByteArray(doubleSignedPDFFile);
//		signatureDataDtos = SignatureUtility.extractSignatures(null, doubleSignPdfContent);
//		Assert.isTrue(signatureDataDtos.size() == 2, "List size is not two");
	}

}
