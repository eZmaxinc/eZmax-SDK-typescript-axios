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


// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingcommissionResponseCompound } from './ezmaxinvoicingcommission-response-compound';

/**
 * 
 * @export
 * @interface EzmaxinvoicingsummaryglobalResponseCompoundAllOf
 */
export interface EzmaxinvoicingsummaryglobalResponseCompoundAllOf {
    /**
     * 
     * @type {Array<EzmaxinvoicingcommissionResponseCompound>}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompoundAllOf
     */
    'a_objEzmaxinvoicingcommission'?: Array<EzmaxinvoicingcommissionResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxinvoicingsummaryglobalResponseCompoundAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingsummaryglobalResponseCompoundAllOf
 */
export class DataObjectEzmaxinvoicingsummaryglobalResponseCompoundAllOf {
   a_objEzmaxinvoicingcommission?:Array<EzmaxinvoicingcommissionResponseCompound> = undefined
}

/**
 * @export 
 * A EzmaxinvoicingsummaryglobalResponseCompoundAllOf Validation Object
 * @class ValidationObjectEzmaxinvoicingsummaryglobalResponseCompoundAllOf
 */
export class ValidationObjectEzmaxinvoicingsummaryglobalResponseCompoundAllOf {
   a_objEzmaxinvoicingcommission = {
      type: 'array',
      required: false
   }
} 


