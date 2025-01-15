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


// May contain unused imports in some cases
// @ts-ignore
import type { PhoneRequestV2 } from './phone-request-v2';

/**
 * @type PhoneRequestCompoundV2
 * A Phone Object and children to create a complete structure
 * @export
 */
/*export type PhoneRequestCompoundV2 = PhoneRequestV2;*/
export interface PhoneRequestCompoundV2 {
    /**
     * The unique ID of the Phone.
     * @type {number}
     * @memberof PhoneRequestCompoundV2
     */
    pkiPhoneID?:number 
    /**
     * The unique ID of the Phonetype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Mobile| |4|Fax| |5|Pager| |6|Toll Free|
     * @type {number}
     * @memberof PhoneRequestCompoundV2
     */
    fkiPhonetypeID:number 
    /**
     * The extension of the phone number.  The extension is the \"123\" section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers
     * @type {string}
     * @memberof PhoneRequestCompoundV2
     */
    sPhoneExtension?:string 
    /**
     * A phone number in E.164 Format
     * @type {string}
     * @memberof PhoneRequestCompoundV2
     */
    sPhoneE164?:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PhoneRequestCompoundV2 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPhoneRequestCompoundV2
 */
export class DataObjectPhoneRequestCompoundV2 {
    pkiPhoneID?:number = undefined
    fkiPhonetypeID:number = 0
    sPhoneExtension?:string = undefined
    sPhoneE164?:string = undefined
}

/**
 * @export 
 * A PhoneRequestCompoundV2 Validation Object
 * @class ValidationObjectPhoneRequestCompoundV2
 */
export class ValidationObjectPhoneRequestCompoundV2 {
   pkiPhoneID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiPhonetypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sPhoneExtension = {
      type: 'string',
      required: false
   }
   sPhoneE164 = {
      type: 'string',
      pattern: /^\+[1-9]\d{1,14}$/,
      required: false
   }
} 


