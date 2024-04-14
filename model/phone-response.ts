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


// May contain unused imports in some cases
// @ts-ignore
import { FieldEPhoneType } from './field-ephone-type';

/**
 * A Phone Object
 * @export
 * @interface PhoneResponse
 */
export interface PhoneResponse {
    /**
     * The unique ID of the Phone.
     * @type {number}
     * @memberof PhoneResponse
     */
    /*'pkiPhoneID': number;*/
    'pkiPhoneID': number;
    /**
     * The unique ID of the Phonetype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Mobile| |4|Fax| |5|Pager| |6|Toll Free|
     * @type {number}
     * @memberof PhoneResponse
     */
    /*'fkiPhonetypeID': number;*/
    'fkiPhonetypeID': number;
    /**
     * 
     * @type {FieldEPhoneType}
     * @memberof PhoneResponse
     * @deprecated
     */
    /*'ePhoneType'?: FieldEPhoneType;*/
    'ePhoneType'?: FieldEPhoneType;
    /**
     * A phone number in E.164 Format
     * @type {string}
     * @memberof PhoneResponse
     */
    /*'sPhoneE164'?: string;*/
    'sPhoneE164'?: string;
    /**
     * The extension of the phone number.  The extension is the \"123\" section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers
     * @type {string}
     * @memberof PhoneResponse
     */
    /*'sPhoneExtension'?: string;*/
    'sPhoneExtension'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PhoneResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPhoneResponse
 */
export class DataObjectPhoneResponse {
   pkiPhoneID:number = 0
   fkiPhonetypeID:number = 0
   ePhoneType?:FieldEPhoneType = undefined
   sPhoneE164?:string = undefined
   sPhoneExtension?:string = undefined
}

/**
 * @export 
 * A PhoneResponse Validation Object
 * @class ValidationObjectPhoneResponse
 */
export class ValidationObjectPhoneResponse {
   pkiPhoneID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiPhonetypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   ePhoneType = {
      type: 'enum',
      allowableValues: ['Local','International'],
      required: false
   }
   sPhoneE164 = {
      type: 'string',
      pattern: '/^\+[1-9]\d{1,14}$/',
      required: false
   }
   sPhoneExtension = {
      type: 'string',
      required: false
   }
} 


