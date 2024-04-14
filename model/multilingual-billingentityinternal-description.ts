/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The description of the Billingentityinternal
 * @export
 * @interface MultilingualBillingentityinternalDescription
 */
export interface MultilingualBillingentityinternalDescription {
    /**
     * The description of the Billingentityinternal in French
     * @type {string}
     * @memberof MultilingualBillingentityinternalDescription
     */
    /*'sBillingentityinternalDescription1'?: string;*/
    'sBillingentityinternalDescription1'?: string;
    /**
     * The description of the Billingentityinternal in English
     * @type {string}
     * @memberof MultilingualBillingentityinternalDescription
     */
    /*'sBillingentityinternalDescription2'?: string;*/
    'sBillingentityinternalDescription2'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A MultilingualBillingentityinternalDescription Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectMultilingualBillingentityinternalDescription
 */
export class DataObjectMultilingualBillingentityinternalDescription {
   sBillingentityinternalDescription1?:string = undefined
   sBillingentityinternalDescription2?:string = undefined
}

/**
 * @export 
 * A MultilingualBillingentityinternalDescription Validation Object
 * @class ValidationObjectMultilingualBillingentityinternalDescription
 */
export class ValidationObjectMultilingualBillingentityinternalDescription {
   sBillingentityinternalDescription1 = {
      type: 'string',
      pattern: '/^.{0,70}$/',
      required: false
   }
   sBillingentityinternalDescription2 = {
      type: 'string',
      pattern: '/^.{0,70}$/',
      required: false
   }
} 


