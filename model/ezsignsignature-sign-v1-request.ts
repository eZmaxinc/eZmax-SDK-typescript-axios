/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/ezsignsignature/{pkiEzsignsignatureID}/sign
 * @export
 * @interface EzsignsignatureSignV1Request
 */
export interface EzsignsignatureSignV1Request {
    /**
     * The value required for the Ezsignsignature.  This can only be set if eEzsignsignatureType is **City**, **FieldText** or **FieldTextarea**
     * @type {string}
     * @memberof EzsignsignatureSignV1Request
     */
    'sValue'?: string;
    /**
     * Indicates if the Ezsignsignature was part of an automatic process or not.  This can only be true if eEzsignsignatureType is **Acknowledgement**, **City**, **Handwritten**, **Initials**, **Name** or **Stamp**. 
     * @type {boolean}
     * @memberof EzsignsignatureSignV1Request
     */
    'bIsAutomatic': boolean;
}
/**
 * A EzsignsignatureSignV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignsignatureSignV1Request
 */
export class DefaultObjectEzsignsignatureSignV1Request extends DefaultObject {
   sValue?:string = undefined
   bIsAutomatic:boolean = false
}


