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
import { FieldEPhoneType } from './field-ephone-type';

/**
 * A Phone Object
 * @export
 * @interface PhoneRequest
 */
export interface PhoneRequest {
    /**
     * The unique ID of the Phone.
     * @type {number}
     * @memberof PhoneRequest
     */
    'pkiPhoneID'?: number;
    /**
     * The unique ID of the Phonetype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Mobile| |4|Fax| |5|Pager| |6|Toll Free|
     * @type {number}
     * @memberof PhoneRequest
     */
    'fkiPhonetypeID': number;
    /**
     * 
     * @type {FieldEPhoneType}
     * @memberof PhoneRequest
     * @deprecated
     */
    'ePhoneType'?: FieldEPhoneType;
    /**
     * The region of the phone number. (For a North America Number only)  The region is the \"514\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof PhoneRequest
     * @deprecated
     */
    'sPhoneRegion'?: string;
    /**
     * The exchange of the phone number. (For a North America Number only)  The exchange is the \"990\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof PhoneRequest
     * @deprecated
     */
    'sPhoneExchange'?: string;
    /**
     * The number of the phone number. (For a North America Number only)  The number is the \"1516\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof PhoneRequest
     * @deprecated
     */
    'sPhoneNumber'?: string;
    /**
     * The international phone number.
     * @type {string}
     * @memberof PhoneRequest
     * @deprecated
     */
    'sPhoneInternational'?: string;
    /**
     * The extension of the phone number.  The extension is the \"123\" section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers
     * @type {string}
     * @memberof PhoneRequest
     */
    'sPhoneExtension'?: string;
    /**
     * A phone number in E.164 Format
     * @type {string}
     * @memberof PhoneRequest
     */
    'sPhoneE164'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PhoneRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPhoneRequest
 */
export class DataObjectPhoneRequest {
   pkiPhoneID?:number = undefined
   fkiPhonetypeID:number = 0
   ePhoneType?:FieldEPhoneType = undefined
   sPhoneRegion?:string = undefined
   sPhoneExchange?:string = undefined
   sPhoneNumber?:string = undefined
   sPhoneInternational?:string = undefined
   sPhoneExtension?:string = undefined
   sPhoneE164?:string = undefined
}

/**
 * @export 
 * A PhoneRequest Validation Object
 * @class ValidationObjectPhoneRequest
 */
export class ValidationObjectPhoneRequest {
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
   ePhoneType = {
      type: 'enum',
      allowableValues: ['Local','International'],
      required: false
   }
   sPhoneRegion = {
      type: 'string',
      required: false
   }
   sPhoneExchange = {
      type: 'string',
      required: false
   }
   sPhoneNumber = {
      type: 'string',
      required: false
   }
   sPhoneInternational = {
      type: 'string',
      required: false
   }
   sPhoneExtension = {
      type: 'string',
      required: false
   }
   sPhoneE164 = {
      type: 'string',
      pattern: '/^\+[1-9]\d{1,14}$/',
      required: false
   }
} 


