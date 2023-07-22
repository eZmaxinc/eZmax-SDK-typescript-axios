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
import { ScimGroupMember } from './scim-group-member';

/**
 * 
 * @export
 * @interface ScimGroup
 */
export interface ScimGroup {
    /**
     * 
     * @type {string}
     * @memberof ScimGroup
     */
    'id'?: string;
    /**
     * The Name of the Usergroup in the language of the requester
     * @type {string}
     * @memberof ScimGroup
     */
    'displayName': string;
    /**
     * 
     * @type {Array<ScimGroupMember>}
     * @memberof ScimGroup
     */
    'members'?: Array<ScimGroupMember>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ScimGroup Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimGroup
 */
export class DataObjectScimGroup {
   id?:string = undefined
   displayName:string = ''
   members?:Array<ScimGroupMember> = undefined
}

/**
 * @export 
 * A ScimGroup Validation Object
 * @class ValidationObjectScimGroup
 */
export class ValidationObjectScimGroup {
   id = {
      type: 'string',
      required: false
   }
   displayName = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: true
   }
   members = {
      type: 'array',
      required: false
   }
} 


