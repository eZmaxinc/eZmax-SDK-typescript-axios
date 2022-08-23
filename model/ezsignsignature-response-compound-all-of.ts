/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsignsignaturecustomdateResponseCompound } from './ezsignsignaturecustomdate-response-compound';

/**
 * 
 * @export
 * @interface EzsignsignatureResponseCompoundAllOf
 */
export interface EzsignsignatureResponseCompoundAllOf {
    /**
     * Whether the Ezsignsignature has a custom date format or not. (Only possible when eEzsignsignatureType is **Name** or **Handwritten**)
     * @type {boolean}
     * @memberof EzsignsignatureResponseCompoundAllOf
     */
    'bEzsignsignatureCustomdate'?: boolean;
    /**
     * An array of custom date blocks that will be filled at the time of signature.  Can only be used if bEzsignsignatureCustomdate is true.  Use an empty array if you don\'t want to have a date at all.
     * @type {Array<EzsignsignaturecustomdateResponseCompound>}
     * @memberof EzsignsignatureResponseCompoundAllOf
     */
    'a_objEzsignsignaturecustomdate'?: Array<EzsignsignaturecustomdateResponseCompound>;
}

