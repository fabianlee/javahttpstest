//http://svn.eparapher.com/trunk/org.eparapher.core/src/main/java/org/eparapher/core/crypto/cert/CertificateInfo.java
package javahttpstest;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.provider.JDKDSAPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

// TO BE DEPRECATED!!!
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;

// DEPRECATED 
//import org.bouncycastle.asn1.DEREncodable;
//import org.bouncycastle.asn1.DERObject;


/**
 * This class parse X509 certificate in order to show text informations for the end user.
 * @author Arnault MICHEL
 */
public class CertificateInfo {

    private static Logger log = Logger.getLogger(CertificateInfo.class);

    /** KeyUsage constants */
    public static final int DIGITALSIGNATURE = 0;
    public static final int NONREPUDIATION = 1;
    public static final int KEYENCIPHERMENT = 2;
    public static final int DATAENCIPHERMENT = 3;
    public static final int KEYAGREEMENT = 4;
    public static final int KEYCERTSIGN = 5;
    public static final int CRLSIGN = 6;
    public static final int ENCIPHERONLY = 7;
    public static final int DECIPHERONLY = 8;

    public static final String[] KEYUSAGETEXTS = { 
        "DIGITALSIGNATURE",
        "NONREPUDIATION",
        "KEYENCIPHERMENT",
        "DATAENCIPHERMENT",
        "KEYAGREEMENT",
        "KEYCERTSIGN",
        "CRLSIGN",
        "ENCIPHERONLY",
        "DECIPHERONLY" };

    /** Extended key usage constants */
    public static final int ANYEXTENDEDKEYUSAGE = 0;
    public static final int SERVERAUTH = 1;
    public static final int CLIENTAUTH = 2;
    public static final int CODESIGNING = 3;
    public static final int EMAILPROTECTION = 4;
    public static final int IPSECENDSYSTEM = 5;
    public static final int IPSECTUNNEL = 6;
    public static final int IPSECUSER = 7;
    public static final int TIMESTAMPING = 8;
    public static final int SMARTCARDLOGON = 9;
    public static final int OCSPSIGNING = 10;

    public static final String[] EXTENDEDKEYUSAGEOIDSTRINGS = {
        "1.3.6.1.5.5.7.3.0",
        "1.3.6.1.5.5.7.3.1",
        "1.3.6.1.5.5.7.3.2",
        "1.3.6.1.5.5.7.3.3",
        "1.3.6.1.5.5.7.3.4",
        "1.3.6.1.5.5.7.3.5",
        "1.3.6.1.5.5.7.3.6",
        "1.3.6.1.5.5.7.3.7",
        "1.3.6.1.5.5.7.3.8",
        "1.3.6.1.4.1.311.20.2.2",
        "1.3.6.1.5.5.7.3.9" };

    public static final String[] EXTENDEDKEYUSAGETEXTS = {
        "ANYEXTENDEDKEYUSAGE",
        "SERVERAUTH",
        "CLIENTAUTH",
        "CODESIGNING",
        "EMAILPROTECTION",
        "IPSECENDSYSTEM",
        "IPSECTUNNEL",
        "IPSECUSER",
        "TIMESTAMPING",
        "SMARTCARDLOGON",
        "OCSPSIGNER" };

    private static final int SUBALTNAME_OTHERNAME = 0;
    private static final int SUBALTNAME_RFC822NAME = 1;
    private static final int SUBALTNAME_DNSNAME = 2;
    private static final int SUBALTNAME_X400ADDRESS = 3;
    private static final int SUBALTNAME_DIRECTORYNAME = 4;
    private static final int SUBALTNAME_EDIPARTYNAME = 5;
    private static final int SUBALTNAME_URI = 6;
    private static final int SUBALTNAME_IPADDRESS = 7;
    private static final int SUBALTNAME_REGISTREDID = 8;

    /** Microsoft altName for windows smart card logon */
    public static final String UPN = "upn";
    /** ObjectID for upn altName for windows smart card logon */
    public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";

    /** Microsoft altName for windows domain controller guid */
    public static final String GUID = "guid";
    /** ObjectID for upn altName for windows domain controller guid */
    public static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";

    private static DateFormat completedateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
    private static DateFormat simpledateFormat   = new SimpleDateFormat("MM/dd/yyyy");

    private X509Certificate certificate;
    private X509Principal subjectdnfieldextractor, issuerdnfieldextractor;
    private String subjectaltnamestring;
    private String subjectdirattrstring;
    private static HashMap<String, String> extendedkeyusageoidtotextmap;

    public CertificateInfo(X509Certificate certificate) {
        this.certificate = certificate;

        subjectdnfieldextractor = new X509Principal(certificate.getSubjectDN().getName());
        issuerdnfieldextractor = new X509Principal(certificate.getIssuerDN().getName());

        // Build HashMap of Extended KeyUsage OIDs (String) to Text representation (String)
        if (extendedkeyusageoidtotextmap == null) {
            extendedkeyusageoidtotextmap = new HashMap<String, String>();
            for (int i = 0; i < EXTENDEDKEYUSAGETEXTS.length; i++)
                extendedkeyusageoidtotextmap.put(EXTENDEDKEYUSAGEOIDSTRINGS[i],
                        EXTENDEDKEYUSAGETEXTS[i]);
        }
    }

    public String getSubjectAltName() {
        if (subjectaltnamestring == null)
            try {
                if (certificate.getSubjectAlternativeNames() != null) {
                    subjectaltnamestring = "";

                    String separator = "";
                    String guid = null;
                    try {
                        guid = getGuidAltName(certificate);
                    } catch (IOException e) {
                        subjectaltnamestring = e.getMessage();
                    }
                    if (guid != null) {
                        subjectaltnamestring += separator + "GUID=" + guid;
                        separator = ", ";
                    }
                    String upn = null;
                    try {
                        upn = getUPNAltName(certificate);
                    } catch (IOException e) {
                        subjectaltnamestring = e.getMessage();
                    }
                    if (upn != null) {
                        subjectaltnamestring += separator + "UPN=" + upn;
                        separator = ", ";
                    }

                    Iterator iter = certificate.getSubjectAlternativeNames()
                    .iterator();
                    while (iter.hasNext()) {
                        List next = (List) iter.next();
                        int OID = ((Integer) next.get(0)).intValue();

                        switch (OID) {
                            case SUBALTNAME_OTHERNAME:
                                // Already taken care of
                                Object obj = next.get(1);
                                if (obj!=null) {
                                    subjectaltnamestring += separator + "OtherName=" + obj.toString();
                                    separator = ", ";
                                }
                                break;
                            case SUBALTNAME_RFC822NAME:
                                subjectaltnamestring += separator + "RFC822Name="
                                + (String) next.get(1);
                                separator = ", ";
                                break;
                            case SUBALTNAME_DNSNAME:
                                subjectaltnamestring += separator + "DNSName="
                                + (String) next.get(1);
                                separator = ", ";
                                break;
                            case SUBALTNAME_X400ADDRESS:
                                //TODO Implement X400ADDRESS
                                break;
                            case SUBALTNAME_EDIPARTYNAME:
                                //TODO Implement EDIPARTYNAME
                                break;
                            case SUBALTNAME_DIRECTORYNAME:
                                //TODO Implement EDIPARTYNAME
                                break;
                            case SUBALTNAME_URI:
                                if (!subjectaltnamestring.equals(""))
                                    subjectaltnamestring += ", ";
                                subjectaltnamestring += separator + "URI="
                                + (String) next.get(1);
                                separator = ", ";
                                break;
                            case SUBALTNAME_IPADDRESS:
                                subjectaltnamestring += separator + "IPAddress="
                                + (String) next.get(1);
                                separator = ", ";
                                break;
                            case SUBALTNAME_REGISTREDID:
                                //TODO implement REGISTREDID
                                break;
                        }

                    }
                }
            } catch (CertificateParsingException e) {
                subjectaltnamestring = e.getMessage();
            }

            return subjectaltnamestring;
    }

    /**
     * Gets the Microsoft specific GUID altName, that is encoded as an octect string.
     *
     * @param cert certificate containing the extension
     * @return String with the hex-encoded GUID byte array or null if the altName does not exist
     */
    public static String getGuidAltName(X509Certificate cert)
    throws IOException, CertificateParsingException {
        Collection altNames = cert.getSubjectAlternativeNames();
        if (altNames != null) {
            Iterator i = altNames.iterator();
            while (i.hasNext()) {
                ASN1Sequence seq = getAltnameSequence((List) i.next());
                if (seq != null) {
                    // First in sequence is the object identifier, that we must check
                    //DERObjectIdentifier id = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
                	DERObjectIdentifier id = (DERObjectIdentifier) DERObjectIdentifier.getInstance(seq.getObjectAt(0));
                    if (id.getId().equals(GUID_OBJECTID)) {
                        ASN1TaggedObject obj = (ASN1TaggedObject) seq
                        .getObjectAt(1);
                        ASN1OctetString str = ASN1OctetString.getInstance(obj
                                .getObject());
                        return new String(Hex.encode(str.getOctets()));
                    }
                }
            }
        }
        return null;
    } // getGuidAltName

    /**
     * Gets the Microsoft specific UPN altName.
     *
     * @param cert certificate containing the extension
     * @return String with the UPN name or null if the altName does not exist
     */
    public static String getUPNAltName(X509Certificate cert)
    throws IOException, CertificateParsingException {
        Collection altNames = cert.getSubjectAlternativeNames();
        if (altNames != null) {
            Iterator i = altNames.iterator();
            while (i.hasNext()) {
                ASN1Sequence seq = getAltnameSequence((List) i.next());
                String ret = getUPNStringFromSequence(seq);
                if (ret != null)
                    return ret;
            }
        }
        return null;
    } // getUPNAltName

    /** Helper method for the above method
     */
    private static String getUPNStringFromSequence(ASN1Sequence seq) {
        if (seq != null) {
            // First in sequence is the object identifier, that we must check
        	// DERObjectIdentifier id = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
            DERObjectIdentifier id = (DERObjectIdentifier) DERObjectIdentifier.getInstance(seq.getObjectAt(0));
            if (id.getId().equals(UPN_OBJECTID)) {
                ASN1TaggedObject obj = (ASN1TaggedObject) seq.getObjectAt(1);
                DERUTF8String str = DERUTF8String.getInstance(obj.getObject());
                return str.getString();
            }
        }
        return null;
    }

    /** Helper for the above methods
     */
    private static ASN1Sequence getAltnameSequence(List listitem)
    throws IOException {
        Integer no = (Integer) listitem.get(0);
        if (no.intValue() == 0) {
            byte[] altName = (byte[]) listitem.get(1);
            return getAltnameSequence(altName);
        }
        return null;
    }

    private static ASN1Sequence getAltnameSequence(byte[] value)
    throws IOException {
    	//DERObject oct = null;
        DERTaggedObject oct = null;
        try {
        	// oct = (new ASN1InputStream(new ByteArrayInputStream(value)).readObject());
            oct = (DERTaggedObject) (new ASN1InputStream(new ByteArrayInputStream(value))
            .readObject());
        } catch (java.io.IOException e) {
            log.error("Error on getting Alt Name as a DERSEquence : " + e.getLocalizedMessage(),e);
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(oct);
        return seq;
    }

    public static String getKeyUsageAsText(X509Certificate certificate){
        if (certificate == null)
            return null;

        String kuText = "";
        boolean[] keyusage = certificate.getKeyUsage();
        if (keyusage == null) return "";
        if (keyusage[0]) kuText += "digitalSignature";
        if (keyusage[1]) kuText += (kuText.equals("")?"":", ") + "nonRepudiation";
        if (keyusage[2]) kuText += (kuText.equals("")?"":", ") + "keyEncipherment";
        if (keyusage[3]) kuText += (kuText.equals("")?"":", ") + "dataEncipherment";
        if (keyusage[4]) kuText += (kuText.equals("")?"":", ") + "keyAgreement";
        if (keyusage[5]) kuText += (kuText.equals("")?"":", ") + "keyCertSign";
        if (keyusage[6]) kuText += (kuText.equals("")?"":", ") + "cRLSign";
        if (keyusage[7]) kuText += (kuText.equals("")?"":", ") + "encipherOnly";
        if (keyusage[8]) kuText += (kuText.equals("")?"":", ") + "decipherOnly";
        return kuText;
    }
    public static String getNSCertTypeAsText(X509Certificate certificate){
        if (certificate == null)
            return null;

        byte[] nct = certificate.getExtensionValue(MiscObjectIdentifiers.netscapeCertType.getId());
		
        if (nct == null) return "";
        String nctText = "";
        if (nct[0]==0) nctText += "SSLClient";
        if (nct[1]==0) nctText += (nctText.equals("")?"":", ") + "SSLServer";
        if (nct[2]==0) nctText += (nctText.equals("")?"":", ") + "S/MIME";
        if (nct[3]==0) nctText += (nctText.equals("")?"":", ") + "Object Signing";
        if (nct[4]==0) nctText += (nctText.equals("")?"":", ") + "Reserved";
        if (nct[5]==0) nctText += (nctText.equals("")?"":", ") + "SSL CA";
        if (nct[6]==0) nctText += (nctText.equals("")?"":", ") + "S/MIME CA";
        if (nct[7]==0) nctText += (nctText.equals("")?"":", ") + "Object Signing CA";
        return nctText;
    }
    @SuppressWarnings("unchecked")
    public static String getExtendedKeyUsageAsText(X509Certificate certificate){
        java.util.List extendedkeyusage = null;

        HashMap<String, String>   extendedkeyusageoidtotextmap = null;
        String[] EXTENDEDKEYUSAGEOIDSTRINGS = { "2.5.29.37.0",
                "1.3.6.1.5.5.7.3.0",
                "1.3.6.1.5.5.7.3.1",
                "1.3.6.1.5.5.7.3.2",
                "1.3.6.1.5.5.7.3.3",
                "1.3.6.1.5.5.7.3.4",
                "1.3.6.1.5.5.7.3.5",
                "1.3.6.1.5.5.7.3.6",
                "1.3.6.1.5.5.7.3.7",
                "1.3.6.1.5.5.7.3.8",
                "1.3.6.1.4.1.311.20.2.2",
        "1.3.6.1.5.5.7.3.9"};

        String[] EXTENDEDKEYUSAGETEXTS = { "All usages",
                "All usages",
                "Server authentication",
                "Client authentication",
                "Code signing",
                "Email protection",
                "IPSec end system",
                "IPSec tunnel",
                "IPSec user",
                "Timestamping",
                "Smartcard Logon",
        "OCSP signer"};

        // Build HashMap of Extended KeyUsage OIDs (String) to Text representation (String)
        extendedkeyusageoidtotextmap = new HashMap<String, String>();
        for(int i=0; i < EXTENDEDKEYUSAGETEXTS.length; i++)
            extendedkeyusageoidtotextmap.put(EXTENDEDKEYUSAGEOIDSTRINGS[i], EXTENDEDKEYUSAGETEXTS[i]);
        try{
            extendedkeyusage = certificate.getExtendedKeyUsage();
        } catch(java.security.cert.CertificateParsingException e){
            log.error("certificate parsing exception" + e.getLocalizedMessage(),e);
            return null;
        }
        if(extendedkeyusage == null)
            extendedkeyusage = new java.util.ArrayList();

        /*String[] returnval = new String[extendedkeyusage.size()];
        for(int i1=0; i1 < extendedkeyusage.size(); i1++){
          returnval[i1] = (String) extendedkeyusageoidtotextmap.get(extendedkeyusage.get(i1));
        }*/

        String returnval = "";
        for(int i=0; i < extendedkeyusage.size(); i++)
            returnval += (returnval.equals("")?"":", ") + extendedkeyusageoidtotextmap.get(extendedkeyusage.get(i));
        return returnval;
    }

    public static String getSubjectAsShortText(X509Certificate certificate) {
    	return certificate.getSubjectDN().getName();
    	/*
        certificate = X509Util.getBCCertificate(certificate);
        return getDNAsShortText(certificate.getSubjectDN());
        */
    }

    public static String getIssuerAsShortText(X509Certificate certificate) {
    	return certificate.getIssuerDN().getName();
    	/*
        certificate = X509Util.getBCCertificate(certificate);
        return getDNAsShortText(certificate.getIssuerDN());
        */
    }

    //TODO : need to be RFC compliant
    public static String getDNAsShortText(Principal dn) {
        X509Principal X509dn = new X509Principal(dn.getName());
        //log.debug("extracting short name from dn " + X509dn);
        if (X509dn!=null && X509dn.getValues(X509Principal.CN).size()>0)
            return X509dn.getValues(X509Principal.CN).get(0).toString();
        else {
            String str_dn = dn.getName();
            int last_equal = str_dn.lastIndexOf("=");
            if (last_equal>=0)
                return str_dn.substring( last_equal+1, str_dn.length());
            return str_dn;
        }
    }

    //TODO : Locale Date?
    //private static DateFormat dateFormat = DateFormat.getDateInstance(DateFormat.FULL, Locale.getDefault());
    public static String getNotBeforeAsText(X509Certificate certificate) {
        return simpledateFormat.format( certificate.getNotBefore() );
    }
    public static String getNotBeforeAsFullText(X509Certificate certificate) {
        return completedateFormat.format( certificate.getNotBefore() );
    }
    public static String getNotAfterAsText(X509Certificate certificate) {
        return simpledateFormat.format( certificate.getNotAfter() );
    }
    public static String getNotAfterAsFullText(X509Certificate certificate) {
        return completedateFormat.format( certificate.getNotAfter() );
    }

    public static String getPublicKeyInfo(PublicKey pk) {
        int keysize = 0;
        String format = pk.getAlgorithm();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pk;
            keysize = (rsapk.getModulus().toByteArray().length -1) * 8;
        }
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpubkey = (JCEECPublicKey) pk;
            keysize = ecpubkey.getQ().getX().getFieldSize();
            //ECParameterSpec ecpspecs = ecpubkey.getParams();
            format = "ECDSA";
            //if ( ecpspecs instanceof ECNamedCurveSpec ) {
            //	ECNamedCurveSpec ecncspec = (ECNamedCurveSpec) ecpspecs;
            //	format += " (" + ecncspec.getName() + ")";
            //}
        }
        if (pk instanceof JDKDSAPublicKey) {
            JDKDSAPublicKey dsapubkey = (JDKDSAPublicKey) pk;
            keysize = dsapubkey.getY().bitLength();
        }

        return  format + " " + keysize + "bits";
    }

    public static List<String> getSubjectAlternativeNames(X509Certificate certificate) {
        List<String> identities = new ArrayList<String>();
        try {
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            // Check that the certificate includes the SubjectAltName extension
            if (altNames == null)
                return Collections.emptyList();
            // Use the type OtherName to search for the certified server name
            for (List item : altNames) {
                Integer type = (Integer) item.get(0);
                if (type == 0)
                    // Type OtherName found so return the associated value
                    try {
                        // Value is encoded using ASN.1 so decode it to get the server's identity
                        ASN1InputStream decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
                        //DEREncodable encoded = decoder.readObject();
                        ASN1Primitive encoded = decoder.readObject();
                        String identity = encoded.toString();
                        /*
                        encoded = ((DERSequence) encoded).getObjectAt(1);
                        encoded = ((DERTaggedObject) encoded).getObject();
                        encoded = ((DERTaggedObject) encoded).getObject();
                        String identity = ((DERUTF8String) encoded).getString();
                        */
                        // Add the decoded server name to the list of identities
                        identities.add(identity);
                    }
                catch (UnsupportedEncodingException e) {
                    log.error("Error decoding subjectAltName" + e.getLocalizedMessage(),e);
                }
                catch (Exception e) {
                    log.error("Error decoding subjectAltName" + e.getLocalizedMessage(),e);
                }
                // Other types are not good for XMPP so ignore them
                log.warn("SubjectAltName of invalid type found: " + certificate);
            }
        }
        catch (CertificateParsingException e) {
            log.error("Error parsing SubjectAltName in certificate: " + certificate + "\r\nerror:" + e.getLocalizedMessage(),e);
        }
        return identities;
    }

    public String getCDPAsText() {

        DistributionPoint[] cdp = null;
        try {
        	byte[] extVal = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        	if(extVal == null)
        		return "";
        	CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
        	cdp = crlDistPoint.getDistributionPoints();
        	/*
            cdp = X509Util.getCrlDistributionPoint(certificate);
            */
        } catch (Exception e) {
            log.error("Error while parsing CDP");
        }
        String returnvalue = "";
        for (DistributionPoint distributionPoint : cdp) {
            if (!returnvalue.equals(""))
                returnvalue += System.getProperty("line.separator");
            if (distributionPoint.getCRLIssuer()!=null)
                returnvalue += distributionPoint.getCRLIssuer() + "=";

            GeneralNames cdpgns = GeneralNames.getInstance(distributionPoint.getDistributionPoint().getName());
            GeneralName[] cdpgn = cdpgns.getNames();
            for (GeneralName element : cdpgn)
                returnvalue += GeneralNameAsText(element);
        }
        return returnvalue;
    }
    public static String GeneralNameAsText(GeneralName gn) {

        StringBuffer buf = new StringBuffer();

        int tag = gn.getTagNo();
        //DEREncodable obj = gn.getName();
        ASN1Encodable obj = gn.getName();

        switch (tag) {
            case GeneralName.rfc822Name:
                buf.append("rfc822Name=");
                buf.append(DERIA5String.getInstance(obj).getString());
                break;
            case GeneralName.dNSName:
                buf.append("dNSName=");
                buf.append(DERIA5String.getInstance(obj).getString());
                break;
            case GeneralName.uniformResourceIdentifier:
                buf.append("URI=");
                buf.append(DERIA5String.getInstance(obj).getString());
                break;
            case GeneralName.directoryName:
                buf.append("directoryName=");
                buf.append(X509Name.getInstance(obj).toString());
                break;
            case GeneralName.ediPartyName:
                buf.append("ediPartyName=");
                buf.append(obj.toString());
                break;
            case GeneralName.iPAddress:
                buf.append("IP=");
                buf.append(obj.toString());
                break;
            case GeneralName.otherName:
                buf.append("otherName=");
                buf.append(obj.toString());
                break;
            case GeneralName.registeredID:
                buf.append("registeredID=");
                buf.append(obj.toString());
                break;
            case GeneralName.x400Address:
                buf.append("x400Address=");
                buf.append(obj.toString());
                break;
            default:
                buf.append(gn.getTagNo()+"=");
        }

        return buf.toString();
    }
}


