package com.pdftool.signature.process;

import com.pdftool.signature.dto.SignatureDataDto;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class ShowPDFSignatures {

    public List<SignatureDataDto> extractSignatures(String password, byte[] contentToBeExtracted ) throws IOException, CertificateException
    {
        List<SignatureDataDto> resultList = new ArrayList<>();

        PDDocument document = null;
        try
        {
            ByteArrayInputStream bis = new ByteArrayInputStream(contentToBeExtracted);
            document = PDDocument.load( bis, password );
            if( !document.isEncrypted() )
            {
                System.err.println( "Warning: Document is not encrypted." );
            }

            COSDictionary trailer = document.getDocument().getTrailer();
            COSDictionary root = (COSDictionary)trailer.getDictionaryObject( COSName.ROOT );
            COSDictionary acroForm = (COSDictionary)root.getDictionaryObject( COSName.ACRO_FORM );
            COSArray fields = (COSArray)acroForm.getDictionaryObject( COSName.FIELDS );
            for( int i=0; i<fields.size(); i++ )
            {
                SignatureDataDto dataDto = new SignatureDataDto();
                COSDictionary field = (COSDictionary)fields.getObject( i );
                COSName type = field.getCOSName( COSName.FT );
                if( COSName.SIG.equals( type ) )
                {
                    COSDictionary cert = (COSDictionary)field.getDictionaryObject( COSName.V );
                    if( cert != null )
                    {
                        System.out.println( "Certificate found" );
                        System.out.println( "Name=" + cert.getDictionaryObject( COSName.NAME ) );
                        System.out.println( "Modified=" + cert.getDictionaryObject( COSName.M ) );
                        dataDto.setName(extractFieldValue(cert, COSName.NAME));
                        dataDto.setModified(extractFieldValue(cert, COSName.M));
                        dataDto.setLocation(extractFieldValue(cert, COSName.LOCATION));
                        dataDto.setReason(extractFieldValue(cert, COSName.REASON));
                        resultList.add(dataDto);
                        COSName subFilter = (COSName)cert.getDictionaryObject( COSName.SUB_FILTER );
                        if( subFilter != null )
                        {
                            if( subFilter.getName().equals( "adbe.x509.rsa_sha1" ) )
                            {
                                COSString certString = (COSString)cert.getDictionaryObject(
                                        COSName.getPDFName( "Cert" ) );
                                byte[] certData = certString.getBytes();
                                CertificateFactory factory = CertificateFactory.getInstance( "X.509" );
                                ByteArrayInputStream certStream = new ByteArrayInputStream( certData );
                                Collection<? extends Certificate> certs = factory.generateCertificates( certStream );
                                System.out.println( "certs=" + certs );
                            }
                            else if( subFilter.getName().startsWith( "adbe.pkcs" ) )
                            {
                                COSString certString = (COSString)cert.getDictionaryObject(
                                        COSName.CONTENTS );
                                String contentHash = extractFieldValue(cert, COSName.CONTENTS);
                                dataDto.setContentHash(contentHash);
                                byte[] certData = certString.getBytes();
                                CertificateFactory factory = CertificateFactory.getInstance( "X.509" );
                                ByteArrayInputStream certStream = new ByteArrayInputStream( certData );
                                Collection<? extends Certificate> certs = factory.generateCertificates( certStream );
                                System.out.println( "certs=" + certs );
                                dataDto.setCertList(certs);
                            }
                            else
                            {
                                System.err.println( "Unknown certificate type:" + subFilter );
                            }
                        }
                        else
                        {
                            throw new IOException( "Missing subfilter for cert dictionary" );
                        }
                    }
                    else
                    {
                        System.out.println( "Signature found, but no certificate" );
                    }
                }
            }
        }
        finally
        {
            if( document != null )
            {
                document.close();
            }
        }

        return resultList;
    }

    private String extractFieldValue(COSDictionary cert, COSName name) {
        String result = new String(((COSString)cert.getDictionaryObject( name )).getBytes());
        return result;
    }
}
