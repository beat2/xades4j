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
package xades4j.properties;

import java.util.Date;

/**
 * Represents a time-stamp computed before the signature production, over the sequence
 * formed by ALL the {@code ds:Reference} elements within the {@code ds:SignedInfo}
 * referencing whatever the signer wants to sign except the SignedProperties element.
 * <p>
 * The {@code AllDataObjectsTimeStamp} element is a signed property. Several
 * instances of this property from different TSAs can occur within the same XAdES.
 *
 * @see IndividualDataObjsTimeStampProperty
 *
 * @author Luís
 */
public final class AllDataObjsTimeStampProperty extends SignedDataObjectProperty
{
    public static final String PROP_NAME = "AllDataObjectsTimeStamp";
    private Date time;

    public AllDataObjsTimeStampProperty()
    {
        super(TargetMultiplicity.ALL);
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }

    /**
     * Gets the time-stamp time after signature production or verification.
     * @return the time or {@code null} if the property wasn't part of a signature production
     */
    public Date getTime()
    {
        return time;
    }

    /**
     * Sets the time-stamp time. This is set during signature production so that
     * the time-stamp can be accessed afterwards.
     * @param time the time
     */
    public void setTime(Date time)
    {
        this.time = time;
    }
}