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
import type { ScimEmail } from './scim-email';

/**
 * 
 * @export
 * @interface ScimUser
 */
export interface ScimUser {
    /**
     * 
     * @type {string}
     * @memberof ScimUser
     */
    /*'id'?: string;*/
    'id'?: string;
    /**
     * A service provider\'s unique identifier for the user, typically used by the user to directly authenticate to the service provider.  Often displayed to the user as their unique identifier within the system (as opposed to \"id\" or \"externalId\", which are generally opaque and not user-friendly identifiers).  Each User MUST include a non-empty userName value.  This identifier MUST be unique across the service provider\'s entire set of Users.  This attribute is REQUIRED and is case insensitive.
     * @type {string}
     * @memberof ScimUser
     */
    /*'userName': string;*/
    'userName': string;
    /**
     * 
     * @type {string}
     * @memberof ScimUser
     */
    /*'displayName'?: string;*/
    'displayName'?: string;
    /**
     * 
     * @type {Array<ScimEmail>}
     * @memberof ScimUser
     */
    /*'emails'?: Array<ScimEmail>;*/
    'emails'?: Array<ScimEmail>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ScimUser Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimUser
 */
export class DataObjectScimUser {
   id?:string = undefined
   userName:string = ''
   displayName?:string = undefined
   emails?:Array<ScimEmail> = undefined
}

/**
 * @export 
 * A ScimUser Validation Object
 * @class ValidationObjectScimUser
 */
export class ValidationObjectScimUser {
   id = {
      type: 'string',
      required: false
   }
   userName = {
      type: 'string',
      required: true
   }
   displayName = {
      type: 'string',
      required: false
   }
   emails = {
      type: 'array',
      required: false
   }
} 


