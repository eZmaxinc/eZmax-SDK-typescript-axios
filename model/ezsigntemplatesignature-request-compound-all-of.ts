/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigntemplatesignaturecustomdateRequestCompound } from './ezsigntemplatesignaturecustomdate-request-compound';

/**
 * 
 * @export
 * @interface EzsigntemplatesignatureRequestCompoundAllOf
 */
export interface EzsigntemplatesignatureRequestCompoundAllOf {
    /**
     * Whether the Ezsigntemplatesignature has a custom date format or not. (Only possible when eEzsigntemplatesignatureType is **Name** or **Handwritten**)
     * @type {boolean}
     * @memberof EzsigntemplatesignatureRequestCompoundAllOf
     */
    'bEzsigntemplatesignatureCustomdate'?: boolean;
    /**
     * An array of custom date blocks that will be filled at the time of signature.  Can only be used if bEzsigntemplatesignatureCustomdate is true.  Use an empty array if you don\'t want to have a date at all.
     * @type {Array<EzsigntemplatesignaturecustomdateRequestCompound>}
     * @memberof EzsigntemplatesignatureRequestCompoundAllOf
     */
    'a_objEzsigntemplatesignaturecustomdate'?: Array<EzsigntemplatesignaturecustomdateRequestCompound>;
}

