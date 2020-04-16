
class CVCertificate(object):
    # Supported tags
    CVC_TAG = 0x7F21
    CVC_BODY_TAG = 0x7F4E
    PROFILE_TAG = 0x5F29
    ISSUER_REF_TAG = 0x42
    PUBLIC_KEY_TAG = 0x7F49
    MODULUS_TAG = 0x81
    E_TAG = 0x82
    HOLDER_REF_TAG = 0x5F20
    SIGNATURE_TAG = 0x5F37

    def __init__(self, cert):
        if CVCertificate.get_tag(cert, 0) != self.CVC_TAG:
            raise ValueError("Expected a CVC object")
        length = CVCertificate.get_length(cert, 2)
        self.cert = cert[5:5 + length]

    """
     * Return the DER tag present in buffer at offset bOff.
     * @param buff
     *      Buffer containing the tag.
     * @param bOff
     *      Offset of the tag in buffer.
     * @return
     *      An int representing the tag.
     
     """
    @staticmethod
    def get_tag(buff, off):
        if (buff[off] & 0x0F) == 0x0F:
            return 0xFFFF & ((buff[off] << 8) | (buff[off + 1] & 0xFF))
        else:
            return 0xFFFF & (buff[off] & 0xFF)

    """
     * Return the length of the field present in buffer at offset bOff.
     * @param buff
     *      Buffer containing the field.
     * @param bOff
     *      Offset of the length in buffer.
     * @return
     *      An int representing the length.
    
    """
    @staticmethod
    def get_length(buff, off):
        if buff[off] == 0x81:
            return buff[off + 1] & 0xFF
        elif buff[off] == 0x82:
            return (buff[off + 1] << 8) | (buff[off + 2] & 0xFF)
        else:
            return buff[off] & 0xFF

    @staticmethod
    def encode_cvc(cert):
        output = [(CVCertificate.CVC_TAG & 0xFF00) >> 8, CVCertificate.CVC_TAG & 0xFF]
        if len(cert) > 65536:
            raise ValueError("Can't use a: bytes long certificate. Max size is 65536".format(len(cert)))
        elif len(cert) > 256:
            output += [0x82, (len(cert) & 0xFF00) >> 8, len(cert) & 0xFF]
        elif len(cert) > 128:
            output += [0x81, len(cert) & 0xFF]
        else:
            output += [len(cert) & 0xFF]
        
        output += cert

        return output

    """
     * Return both the offset and the length of a specific field of buffer.
     * @param cert
     *      Buffer containing the field.
     * @param tagElt
     *      Tag of the element.
     * @return
     *      An array representing the offset and the length of the element.
    """
    @staticmethod
    def get_elt_info(buff, tag_elt):
        off = 0

        while off < len(buff)-2:
            tag = CVCertificate.get_tag(buff, off)
            off += 1 if (tag & 0xFF00) == 0 else 2
            length = CVCertificate.get_length(buff, off)
            if length >= 0x80:
                off += 1
            if length > 0xFF:
                off += 1
            off += 1

            if tag == tag_elt:
                return off, length

            off += length

        return None

    """
     * Get an element corresponding to a TLV tag.
     * @param cert
     *      Intput buffer, containing the element we look for.
     * @param tagElt
     *      Tag of the element we look for.
     * @return
     *      The element corresponding to the tag.
    """
    @staticmethod
    def get_elt(buff, tag_elt):
        offset, length = CVCertificate.get_elt_info(buff, tag_elt)
        
        return buff[offset: offset+length]

    def get_encoded(self):
        output = [(self.CVC_TAG & 0xFF00) >> 8, self.CVC_TAG & 0xFF]
        
        if len(self.cert) > 65536:
            raise ValueError("Can't use a: bytes long certificate. Max size is 65536".format(len(self.cert)))
        elif len(self.cert) > 256:
            output += [0x82, (len(self.cert) & 0xFF00) >> 8, len(self.cert) & 0xFF]
        elif len(self.cert) > 128:
            output += [0x81, len(self.cert) & 0xFF]
        else:
            output += [len(self.cert) & 0xFF]
        
        output += self.cert

        return output

    def get_signature(self):
        return CVCertificate.get_elt(self.cert, self.SIGNATURE_TAG)

    def get_body(self):
        return CVCertificate.get_elt(self.cert, self.CVC_BODY_TAG)

    def get_issuer_ref(self):
        return CVCertificate.get_elt(self.get_body(), self.ISSUER_REF_TAG)

    def get_holder_ref(self):
        return CVCertificate.get_elt(self.get_body(), self.HOLDER_REF_TAG)
    
    def get_pub(self):
        body = self.get_body()
        public_key = CVCertificate.get_elt(body, self.PUBLIC_KEY_TAG)
        n = int.from_bytes(CVCertificate.get_elt(public_key, self.MODULUS_TAG), byteorder='big')
        e = int.from_bytes(CVCertificate.get_elt(public_key, self.E_TAG), byteorder='big')

        return n, e
