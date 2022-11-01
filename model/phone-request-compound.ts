/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
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

import { DefaultObject } from '../base'

/**
 * @type PhoneRequestCompound
 * A Phone Object and children to create a complete structure
 * @export
 */
export type PhoneRequestCompound = PhoneRequest;


/**
 * @export 
 * A PhoneRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectPhoneRequestCompound
 */
export class DefaultObjectPhoneRequestCompound extends DefaultObject {
   fkiPhonetypeID:number = 0
   ePhoneType:FieldEPhoneType = 'Local'
   sPhoneRegion?:string = undefined
   sPhoneExchange?:string = undefined
   sPhoneNumber?:string = undefined
   sPhoneInternational?:string = undefined
   sPhoneExtension?:string = undefined
}


