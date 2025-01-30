/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Creditcardmerchant AutocompleteElement Response
 * @export
 * @interface CreditcardmerchantAutocompleteElementResponse
 */
export interface CreditcardmerchantAutocompleteElementResponse {
    /**
     * The unique ID of the Creditcardmerchant
     * @type {number}
     * @memberof CreditcardmerchantAutocompleteElementResponse
     */
    /*'pkiCreditcardmerchantID': number;*/
    'pkiCreditcardmerchantID': number;
    /**
     * The description of the Creditcardmerchant
     * @type {string}
     * @memberof CreditcardmerchantAutocompleteElementResponse
     */
    /*'sCreditcardmerchantDescription': string;*/
    'sCreditcardmerchantDescription': string;
    /**
     * Whether the creditcardmerchant is active or not
     * @type {boolean}
     * @memberof CreditcardmerchantAutocompleteElementResponse
     */
    /*'bCreditcardmerchantIsactive': boolean;*/
    'bCreditcardmerchantIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CreditcardmerchantAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardmerchantAutocompleteElementResponse
 */
export class DataObjectCreditcardmerchantAutocompleteElementResponse {
   pkiCreditcardmerchantID:number = 0
   sCreditcardmerchantDescription:string = ''
   bCreditcardmerchantIsactive:boolean = false
}

/**
 * @export 
 * A CreditcardmerchantAutocompleteElementResponse Validation Object
 * @class ValidationObjectCreditcardmerchantAutocompleteElementResponse
 */
export class ValidationObjectCreditcardmerchantAutocompleteElementResponse {
   pkiCreditcardmerchantID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sCreditcardmerchantDescription = {
      type: 'string',
      pattern: /^.{0,25}$/,
      required: true
   }
   bCreditcardmerchantIsactive = {
      type: 'boolean',
      required: true
   }
} 


