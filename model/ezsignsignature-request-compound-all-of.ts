/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignaturecustomdateRequestCompound } from './ezsignsignaturecustomdate-request-compound';

/**
 * 
 * @export
 * @interface EzsignsignatureRequestCompoundAllOf
 */
export interface EzsignsignatureRequestCompoundAllOf {
    /**
     * Whether the Ezsignsignature has a custom date format or not. (Only possible when eEzsignsignatureType is **Name** or **Handwritten**)
     * @type {boolean}
     * @memberof EzsignsignatureRequestCompoundAllOf
     */
    'bEzsignsignatureCustomdate'?: boolean;
    /**
     * An array of custom date blocks that will be filled at the time of signature.  Can only be used if bEzsignsignatureCustomdate is true.  Use an empty array if you don\'t want to have a date at all.
     * @type {Array<EzsignsignaturecustomdateRequestCompound>}
     * @memberof EzsignsignatureRequestCompoundAllOf
     */
    'a_objEzsignsignaturecustomdate'?: Array<EzsignsignaturecustomdateRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignatureRequestCompoundAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureRequestCompoundAllOf
 */
export class DataObjectEzsignsignatureRequestCompoundAllOf {
   bEzsignsignatureCustomdate?:boolean = undefined
   a_objEzsignsignaturecustomdate?:Array<EzsignsignaturecustomdateRequestCompound> = undefined
}

/**
 * @export 
 * A EzsignsignatureRequestCompoundAllOf Validation Object
 * @class ValidationObjectEzsignsignatureRequestCompoundAllOf
 */
export class ValidationObjectEzsignsignatureRequestCompoundAllOf {
   bEzsignsignatureCustomdate = {
      type: 'boolean',
      required: false
   }
   a_objEzsignsignaturecustomdate = {
      type: 'array',
      required: false
   }
} 


