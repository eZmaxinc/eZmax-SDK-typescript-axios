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
import { AddressRequest } from './address-request';

/**
 * @type AddressRequestCompound
 * An Address Object and children to create a complete structure
 * @export
 */
export type AddressRequestCompound = AddressRequest;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A AddressRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAddressRequestCompound
 */
export class DataObjectAddressRequestCompound {
    fkiAddresstypeID:number = 0
    sAddressCivic:string = ''
    sAddressStreet:string = ''
    sAddressSuite:string = ''
    sAddressCity:string = ''
    fkiProvinceID:number = 0
    fkiCountryID:number = 0
    sAddressZip:string = ''
}

/**
 * @export 
 * A AddressRequestCompound Validation Object
 * @class ValidationObjectAddressRequestCompound
 */
export class ValidationObjectAddressRequestCompound {
   fkiAddresstypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sAddressCivic = {
      type: 'string',
      required: true
   }
   sAddressStreet = {
      type: 'string',
      required: true
   }
   sAddressSuite = {
      type: 'string',
      required: true
   }
   sAddressCity = {
      type: 'string',
      required: true
   }
   fkiProvinceID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiCountryID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sAddressZip = {
      type: 'string',
      required: true
   }
} 


