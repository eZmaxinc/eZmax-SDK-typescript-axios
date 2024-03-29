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
import { PhonestaticResponse } from './phonestatic-response';

/**
 * @type PhonestaticResponseCompound
 * A Phonestatic Object and children to create a complete structure
 * @export
 */
export type PhonestaticResponseCompound = PhonestaticResponse;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PhonestaticResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPhonestaticResponseCompound
 */
export class DataObjectPhonestaticResponseCompound {
    pkiPhonestaticID:number = 0
    sPhonestaticE164?:string = undefined
    sPhonestaticExtension?:string = undefined
}

/**
 * @export 
 * A PhonestaticResponseCompound Validation Object
 * @class ValidationObjectPhonestaticResponseCompound
 */
export class ValidationObjectPhonestaticResponseCompound {
   pkiPhonestaticID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sPhonestaticE164 = {
      type: 'string',
      pattern: '/^\+[1-9]\d{1,14}$/',
      required: false
   }
   sPhonestaticExtension = {
      type: 'string',
      pattern: '/^\d/',
      required: false
   }
} 


