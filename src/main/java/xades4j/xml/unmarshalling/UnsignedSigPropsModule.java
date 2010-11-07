/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.xml.unmarshalling;

import org.w3c.dom.Element;
import xades4j.utils.DOMHelper;
import xades4j.xml.bind.xades.XmlQualifyingPropertiesType;
import xades4j.xml.bind.xades.XmlUnsignedPropertiesType;
import xades4j.xml.bind.xades.XmlUnsignedSignaturePropertiesType;

/**
 *
 * @author Luís
 */
class UnsignedSigPropsModule extends UnmarshallerModule<XmlUnsignedSignaturePropertiesType>
{
    private final FromXmlUnknownUnsignedSigPropsConverter unknownUnsignedSigPropsConv;

    UnsignedSigPropsModule()
    {
        super(5);
        super.addConverter(new FromXmlSignatureTimeStampConverter());
        super.addConverter(new FromXmlCompleteCertRefsConverter());
        super.addConverter(new FromXmlCompleteRevocRefsConverter());
        this.unknownUnsignedSigPropsConv = new FromXmlUnknownUnsignedSigPropsConverter();
        super.addConverter(unknownUnsignedSigPropsConv);
        super.addConverter(new FromXmlUnsupportedUSPLimiter());
        /**/
        super.addConverter(new FromDOMCounterSignatureConverter());
    }

    @Override
    protected XmlUnsignedSignaturePropertiesType getXmlProps(
            XmlQualifyingPropertiesType xmlQualifProps)
    {
        XmlUnsignedPropertiesType xmlUnsignedProps = xmlQualifProps.getUnsignedProperties();
        return null == xmlUnsignedProps ? null : xmlUnsignedProps.getUnsignedSignatureProperties();
    }

    @Override
    protected Element getProps(Element qualifProps)
    {
        // This method is invoked only if the specifi properties element is present.
        return DOMHelper.getLastChildElement(DOMHelper.getLastChildElement(qualifProps));
    }

    @Override
    protected void setAcceptUnknownProperties(boolean accept)
    {
        this.unknownUnsignedSigPropsConv.setAcceptUnknownProperties(accept);
    }
}