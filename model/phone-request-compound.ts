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
// May contain unused imports in some cases
// @ts-ignore
import { PhoneRequest } from './phone-request';

/**
 * @type PhoneRequestCompound
 * A Phone Object and children to create a complete structure
 * @export
 */
/** export type PhoneRequestCompound = PhoneRequest; */
export interface PhoneRequestCompound {
    /**
     * The unique ID of the Phone.
     * @type {number}
     * @memberof PhoneRequestCompound
     */
    pkiPhoneID?:number 
    /**
     * The unique ID of the Phonetype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Mobile| |4|Fax| |5|Pager| |6|Toll Free|
     * @type {number}
     * @memberof PhoneRequestCompound
     */
    fkiPhonetypeID:number 
    /**
     * 
     * @type {FieldEPhoneType}
     * @memberof PhoneRequestCompound
     * @deprecated
     */
    ePhoneType?:FieldEPhoneType 
    /**
     * The region of the phone number. (For a North America Number only)  The region is the \"514\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof PhoneRequestCompound
     * @deprecated
     */
    sPhoneRegion?:string 
    /**
     * The exchange of the phone number. (For a North America Number only)  The exchange is the \"990\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof PhoneRequestCompound
     * @deprecated
     */
    sPhoneExchange?:string 
    /**
     * The number of the phone number. (For a North America Number only)  The number is the \"1516\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof PhoneRequestCompound
     * @deprecated
     */
    sPhoneNumber?:string 
    /**
     * The international phone number.
     * @type {string}
     * @memberof PhoneRequestCompound
     * @deprecated
     */
    sPhoneInternational?:string 
    /**
     * The extension of the phone number.  The extension is the \"123\" section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers
     * @type {string}
     * @memberof PhoneRequestCompound
     */
    sPhoneExtension?:string 
    /**
     * A phone number in E.164 Format
     * @type {string}
     * @memberof PhoneRequestCompound
     */
    sPhoneE164?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PhoneRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPhoneRequestCompound
 */
export class DataObjectPhoneRequestCompound {
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
 * A PhoneRequestCompound Validation Object
 * @class ValidationObjectPhoneRequestCompound
 */
export class ValidationObjectPhoneRequestCompound {
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


