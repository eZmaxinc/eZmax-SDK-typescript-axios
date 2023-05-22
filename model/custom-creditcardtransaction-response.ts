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



/**
 * A custom Creditcardtransaction Object
 * @export
 * @interface CustomCreditcardtransactionResponse
 */
export interface CustomCreditcardtransactionResponse {
    /**
     * The codename of the Creditcardtype
     * @type {string}
     * @memberof CustomCreditcardtransactionResponse
     */
    'sCreditcardtypeCodename': string;
    /**
     * The amount of the Creditcardtransaction
     * @type {string}
     * @memberof CustomCreditcardtransactionResponse
     */
    'dCreditcardtransactionAmount': string;
    /**
     * The partially decrypted credit card number used in the Creditcardtransaction
     * @type {string}
     * @memberof CustomCreditcardtransactionResponse
     */
    'sCreditcardtransactionPartiallydecryptednumber': string;
    /**
     * The reference number on the creditcard service for the Creditcardtransaction
     * @type {string}
     * @memberof CustomCreditcardtransactionResponse
     */
    'sCreditcardtransactionReferencenumber': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomCreditcardtransactionResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomCreditcardtransactionResponse
 */
export class DataObjectCustomCreditcardtransactionResponse {
   sCreditcardtypeCodename:string = ''
   dCreditcardtransactionAmount:string = ''
   sCreditcardtransactionPartiallydecryptednumber:string = ''
   sCreditcardtransactionReferencenumber:string = ''
}

/**
 * @export 
 * A CustomCreditcardtransactionResponse Validation Object
 * @class ValidationObjectCustomCreditcardtransactionResponse
 */
export class ValidationObjectCustomCreditcardtransactionResponse {
   sCreditcardtypeCodename = {
      type: 'string',
      pattern: '/^[a-zA-Z ]{0,15}$/',
      required: true
   }
   dCreditcardtransactionAmount = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   sCreditcardtransactionPartiallydecryptednumber = {
      type: 'string',
      pattern: '/^([X]{4}[ ]){3}(\d){4}$/',
      required: true
   }
   sCreditcardtransactionReferencenumber = {
      type: 'string',
      pattern: '/^[\d]{18}$/',
      required: true
   }
} 


