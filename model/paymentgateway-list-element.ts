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
import type { FieldEPaymentgatewayProcessor } from './field-epaymentgateway-processor';

/**
 * A Paymentgateway List Element
 * @export
 * @interface PaymentgatewayListElement
 */
export interface PaymentgatewayListElement {
    /**
     * The unique ID of the Paymentgateway
     * @type {number}
     * @memberof PaymentgatewayListElement
     */
    /*'pkiPaymentgatewayID': number;*/
    'pkiPaymentgatewayID': number;
    /**
     * The unique ID of the Creditcardmerchant
     * @type {number}
     * @memberof PaymentgatewayListElement
     */
    /*'fkiCreditcardmerchantID': number;*/
    'fkiCreditcardmerchantID': number;
    /**
     * 
     * @type {FieldEPaymentgatewayProcessor}
     * @memberof PaymentgatewayListElement
     */
    /*'ePaymentgatewayProcessor': FieldEPaymentgatewayProcessor;*/
    'ePaymentgatewayProcessor': FieldEPaymentgatewayProcessor;
    /**
     * The description of the Paymentgateway in the language of the requester
     * @type {string}
     * @memberof PaymentgatewayListElement
     */
    /*'sPaymentgatewayDescriptionX': string;*/
    'sPaymentgatewayDescriptionX': string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PaymentgatewayListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymentgatewayListElement
 */
export class DataObjectPaymentgatewayListElement {
   pkiPaymentgatewayID:number = 0
   fkiCreditcardmerchantID:number = 0
   ePaymentgatewayProcessor:FieldEPaymentgatewayProcessor = 'Moneris'
   sPaymentgatewayDescriptionX:string = ''
}

/**
 * @export 
 * A PaymentgatewayListElement Validation Object
 * @class ValidationObjectPaymentgatewayListElement
 */
export class ValidationObjectPaymentgatewayListElement {
   pkiPaymentgatewayID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiCreditcardmerchantID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   ePaymentgatewayProcessor = {
      type: 'enum',
      allowableValues: ['Moneris'],
      required: true
   }
   sPaymentgatewayDescriptionX = {
      type: 'string',
      pattern: /^.{1,50}$/,
      required: true
   }
} 


