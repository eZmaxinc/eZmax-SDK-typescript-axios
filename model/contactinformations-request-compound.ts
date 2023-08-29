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
import { AddressRequestCompound } from './address-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { ContactinformationsRequest } from './contactinformations-request';
// May contain unused imports in some cases
// @ts-ignore
import { EmailRequestCompound } from './email-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { PhoneRequestCompound } from './phone-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { WebsiteRequestCompound } from './website-request-compound';

/**
 * @type ContactinformationsRequestCompound
 * A Contactinformations Object and children to create a complete structure
 * @export
 */
export type ContactinformationsRequestCompound = ContactinformationsRequest;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ContactinformationsRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContactinformationsRequestCompound
 */
export class DataObjectContactinformationsRequestCompound {
    iAddressDefault:number = 0
    iPhoneDefault:number = 0
    iEmailDefault:number = 0
    iWebsiteDefault:number = 0
    a_objAddress:Array<AddressRequestCompound> = []
    a_objPhone:Array<PhoneRequestCompound> = []
    a_objEmail:Array<EmailRequestCompound> = []
    a_objWebsite:Array<WebsiteRequestCompound> = []
}

/**
 * @export 
 * A ContactinformationsRequestCompound Validation Object
 * @class ValidationObjectContactinformationsRequestCompound
 */
export class ValidationObjectContactinformationsRequestCompound {
   iAddressDefault = {
      type: 'integer',
      required: true
   }
   iPhoneDefault = {
      type: 'integer',
      required: true
   }
   iEmailDefault = {
      type: 'integer',
      required: true
   }
   iWebsiteDefault = {
      type: 'integer',
      required: true
   }
   a_objAddress = {
      type: 'array',
      required: true
   }
   a_objPhone = {
      type: 'array',
      required: true
   }
   a_objEmail = {
      type: 'array',
      required: true
   }
   a_objWebsite = {
      type: 'array',
      required: true
   }
} 


