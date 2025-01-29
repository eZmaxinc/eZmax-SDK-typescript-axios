/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Creditcardclient Object
 * @export
 * @interface CreditcardclientRequestPatch
 */
export interface CreditcardclientRequestPatch {
    /**
     * Whether if it\'s the creditcardclient is the default one
     * @type {boolean}
     * @memberof CreditcardclientRequestPatch
     */
    /*'bCreditcardclientrelationIsdefault'?: boolean;*/
    'bCreditcardclientrelationIsdefault'?: boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CreditcardclientRequestPatch Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardclientRequestPatch
 */
export class DataObjectCreditcardclientRequestPatch {
   bCreditcardclientrelationIsdefault?:boolean = undefined
}

/**
 * @export 
 * A CreditcardclientRequestPatch Validation Object
 * @class ValidationObjectCreditcardclientRequestPatch
 */
export class ValidationObjectCreditcardclientRequestPatch {
   bCreditcardclientrelationIsdefault = {
      type: 'boolean',
      required: false
   }
} 


