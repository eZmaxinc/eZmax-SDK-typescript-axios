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


// May contain unused imports in some cases
// @ts-ignore
import type { FieldECreditcardtransactionAvsresult } from './field-ecreditcardtransaction-avsresult';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldECreditcardtransactionCvdresult } from './field-ecreditcardtransaction-cvdresult';

/**
 * A custom Creditcardtransactionresponse Object
 * @export
 * @interface CustomCreditcardtransactionresponseResponse
 */
export interface CustomCreditcardtransactionresponseResponse {
    /**
     * The ISO code
     * @type {string}
     * @memberof CustomCreditcardtransactionresponseResponse
     */
    /*'sCreditcardtransactionISOcode': string;*/
    'sCreditcardtransactionISOcode': string;
    /**
     * The response code
     * @type {string}
     * @memberof CustomCreditcardtransactionresponseResponse
     */
    /*'sCreditcardtransactionResponsecode': string;*/
    'sCreditcardtransactionResponsecode': string;
    /**
     * The terminal response message
     * @type {string}
     * @memberof CustomCreditcardtransactionresponseResponse
     */
    /*'sCreditcardtransactionResponseterminalmessage': string;*/
    'sCreditcardtransactionResponseterminalmessage': string;
    /**
     * 
     * @type {FieldECreditcardtransactionAvsresult}
     * @memberof CustomCreditcardtransactionresponseResponse
     */
    /*'eCreditcardtransactionAvsresult'?: FieldECreditcardtransactionAvsresult;*/
    'eCreditcardtransactionAvsresult'?: FieldECreditcardtransactionAvsresult;
    /**
     * 
     * @type {FieldECreditcardtransactionCvdresult}
     * @memberof CustomCreditcardtransactionresponseResponse
     */
    /*'eCreditcardtransactionCvdresult'?: FieldECreditcardtransactionCvdresult;*/
    'eCreditcardtransactionCvdresult'?: FieldECreditcardtransactionCvdresult;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomCreditcardtransactionresponseResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomCreditcardtransactionresponseResponse
 */
export class DataObjectCustomCreditcardtransactionresponseResponse {
   sCreditcardtransactionISOcode:string = ''
   sCreditcardtransactionResponsecode:string = ''
   sCreditcardtransactionResponseterminalmessage:string = ''
   eCreditcardtransactionAvsresult?:FieldECreditcardtransactionAvsresult = undefined
   eCreditcardtransactionCvdresult?:FieldECreditcardtransactionCvdresult = undefined
}

/**
 * @export 
 * A CustomCreditcardtransactionresponseResponse Validation Object
 * @class ValidationObjectCustomCreditcardtransactionresponseResponse
 */
export class ValidationObjectCustomCreditcardtransactionresponseResponse {
   sCreditcardtransactionISOcode = {
      type: 'string',
      pattern: /^.{1,2}$/,
      required: true
   }
   sCreditcardtransactionResponsecode = {
      type: 'string',
      pattern: /^.{1,3}$/,
      required: true
   }
   sCreditcardtransactionResponseterminalmessage = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
   eCreditcardtransactionAvsresult = {
      type: 'enum',
      allowableValues: ['Match','NoMatch','PartialMatch','NotImplemented','NotVerified'],
      required: false
   }
   eCreditcardtransactionCvdresult = {
      type: 'enum',
      allowableValues: ['Match','NoMatch','NotVerified'],
      required: false
   }
} 


