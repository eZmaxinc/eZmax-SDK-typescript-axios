/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { UserstagedResponse } from './userstaged-response';

/**
 * @type UserstagedResponseCompound
 * A Userstaged Object
 * @export
 */
export type UserstagedResponseCompound = UserstagedResponse;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserstagedResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedResponseCompound
 */
export class DataObjectUserstagedResponseCompound {
   pkiUserstagedID:number = 0
   fkiEmailID:number = 0
   sUserstagedFirstname:string = ''
   sUserstagedLastname:string = ''
   sUserstagedExternalid:string = ''
}

/**
 * @export 
 * A UserstagedResponseCompound Validation Object
 * @class ValidationObjectUserstagedResponseCompound
 */
export class ValidationObjectUserstagedResponseCompound {
   pkiUserstagedID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: true
   }
   fkiEmailID = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: true
   }
   sUserstagedFirstname = {
      type: 'string',
      pattern: '/^.{0,20}$/',
      required: true
   }
   sUserstagedLastname = {
      type: 'string',
      pattern: '/^.{0,25}$/',
      required: true
   }
   sUserstagedExternalid = {
      type: 'string',
      pattern: '/^.{1,60}$/',
      required: true
   }
} 


