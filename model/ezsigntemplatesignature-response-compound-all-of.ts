/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigntemplatesignaturecustomdateResponseCompound } from './ezsigntemplatesignaturecustomdate-response-compound';

/**
 * 
 * @export
 * @interface EzsigntemplatesignatureResponseCompoundAllOf
 */
export interface EzsigntemplatesignatureResponseCompoundAllOf {
    /**
     * Whether the Ezsigntemplatesignature has a custom date format or not. (Only possible when eEzsigntemplatesignatureType is **Name** or **Handwritten**)
     * @type {boolean}
     * @memberof EzsigntemplatesignatureResponseCompoundAllOf
     */
    'bEzsigntemplatesignatureCustomdate'?: boolean;
    /**
     * An array of custom date blocks that will be filled at the time of signature.  Can only be used if bEzsigntemplatesignatureCustomdate is true.  Use an empty array if you don\'t want to have a date at all.
     * @type {Array<EzsigntemplatesignaturecustomdateResponseCompound>}
     * @memberof EzsigntemplatesignatureResponseCompoundAllOf
     */
    'a_objEzsigntemplatesignaturecustomdate'?: Array<EzsigntemplatesignaturecustomdateResponseCompound>;
}

