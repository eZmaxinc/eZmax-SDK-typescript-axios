/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignaturecustomdateResponseCompound } from './ezsigntemplatesignaturecustomdate-response-compound';

import { DefaultObject } from '../base'

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
/**
 * A EzsigntemplatesignatureResponseCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignatureResponseCompoundAllOf
 */
export class DefaultObjectEzsigntemplatesignatureResponseCompoundAllOf extends DefaultObject {
   bEzsigntemplatesignatureCustomdate?:boolean = undefined
   a_objEzsigntemplatesignaturecustomdate?:Array<EzsigntemplatesignaturecustomdateResponseCompound> = undefined
}


