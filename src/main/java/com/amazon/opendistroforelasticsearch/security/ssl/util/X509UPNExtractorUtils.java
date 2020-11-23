package com.amazon.opendistroforelasticsearch.security.ssl.util;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import com.google.common.base.Predicates;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Credential to principal resolver that extracts Subject Alternative Name UPN extension
 * from the provided certificate if available as a resolved principal id.
 *
 * @author Dmitriy Kopylenko
 * @author Hal Deadman
 * @since 4.1.0
 */
public class X509UPNExtractorUtils {

    private static final Logger log = LogManager.getLogger(X509UPNExtractorUtils.class);

    /**
     * ObjectID for upn altName for windows smart card logon.
     */
    private static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";

    /**
     * Integer representing the type of the subject alt name known as OtherName or ANY.
     */
    private static final int SAN_TYPE_OTHER = 0;

    /**
     * Do if function.
     *
     * @param <T>           the type parameter
     * @param <R>           the type parameter
     * @param condition     the condition
     * @param trueFunction  the true function
     * @param falseFunction the false function
     * @return the function
     */
    public static <T, R> Function<T, R> doIf(final Predicate<Object> condition, final Supplier<R> trueFunction,
                                             final Supplier<R> falseFunction) {
        return t -> {
            try {
                if (condition.test(t)) {
                    return trueFunction.get();
                }
                return falseFunction.get();
            } catch (final Throwable e) {
                return falseFunction.get();
            }
        };
    }



    /**
     * Get UPN String.
     *
     * @param seq ASN1Sequence abstraction representing subject alternative name.
     *            First element is the object identifier, second is the object itself.
     * @return UPN string or null
     */
    private static String getUPNStringFromSequence(final ASN1Sequence seq) {
        if (seq == null) {
            return null;
        }
        ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        if (id != null && UPN_OBJECTID.equals(id.getId())) {
            ASN1TaggedObject obj = (ASN1TaggedObject) seq.getObjectAt(1);
            Object primitiveObj = obj.getObject();

            Function func = doIf(Predicates.instanceOf(ASN1TaggedObject.class),
                () -> ASN1TaggedObject.getInstance(primitiveObj).getObject(),
                () -> primitiveObj);
            Object prim = func.apply(primitiveObj);

            if (prim instanceof ASN1OctetString) {
                return new String(((ASN1OctetString) prim).getOctets(), StandardCharsets.UTF_8);
            }
            if (prim instanceof ASN1String) {
                return ((ASN1String) prim).getString();
            }
        }
        return null;
    }

    /**
     * Get alt name seq.
     *
     * @param sanValue subject alternative name value encoded as byte[]
     * @return ASN1Sequence abstraction representing subject alternative name
     * @see <a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/cert/X509Certificate.html#getSubjectAlternativeNames()">
     * X509Certificate#getSubjectAlternativeNames</a>
     */
    private static ASN1Sequence getAltnameSequence(final byte[] sanValue) {
        try (ByteArrayInputStream bInput = new ByteArrayInputStream(sanValue);
             ASN1InputStream input = new ASN1InputStream(bInput)) {
            return ASN1Sequence.getInstance(input.readObject());
        } catch (final IOException e) {
            log.error(log, e);
        }
        return null;
    }

    /**
     * Return the first {@code X509UPNExtractorUtils.UPN_OBJECTID} found in the subject alternative names (SAN) extension field of the certificate.
     * @param certificate X509 certificate
     * @return User principal name, or null if no SAN found matching UPN type.
     * @throws CertificateParsingException if Java retrieval of subject alt names fails.
     */
    public static String getSANString(final X509Certificate certificate) throws CertificateParsingException {
        Collection<List<?>> subjectAltNames = certificate.getSubjectAlternativeNames();
        List subjectAltNamesResult = new ArrayList();
        if (subjectAltNames != null) {
            for (List<?> sanItem : subjectAltNames) {
                    if (sanItem.size() == 2) {
                        Object name = sanItem.get(1);
                        Integer itemType = (Integer) sanItem.get(0);
                        if (itemType == SAN_TYPE_OTHER) {
                            byte[] altName = (byte[]) sanItem.get(1);
                            final ASN1Sequence seq = getAltnameSequence(altName);
                            final String upnString = getUPNStringFromSequence(seq);
                            subjectAltNamesResult.add(Arrays.asList(itemType, upnString));
                        } else {
                            subjectAltNamesResult.add(Arrays.asList(itemType, ((String) sanItem.get(1)).toString()));
                        }

                        if (log.isTraceEnabled()) {
                            log.trace("Found subject alt name of type [{}] with value [{}]",
                                sanItem.get(0), name instanceof String ? name : name instanceof byte[] ? getAltnameSequence((byte[]) name) : name);
                        }
                    }
                }
            }
        return subjectAltNamesResult.toString();
    }
}
