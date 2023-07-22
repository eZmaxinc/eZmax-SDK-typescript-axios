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
import { UsergroupListElement } from './usergroup-list-element';

/**
 * 
 * @export
 * @interface UsergroupGetListV1ResponseMPayloadAllOf
 */
export interface UsergroupGetListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<UsergroupListElement>}
     * @memberof UsergroupGetListV1ResponseMPayloadAllOf
     */
    'a_objUsergroup': Array<UsergroupListElement>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupGetListV1ResponseMPayloadAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupGetListV1ResponseMPayloadAllOf
 */
export class DataObjectUsergroupGetListV1ResponseMPayloadAllOf {
   a_objUsergroup:Array<UsergroupListElement> = []
}

/**
 * @export 
 * A UsergroupGetListV1ResponseMPayloadAllOf Validation Object
 * @class ValidationObjectUsergroupGetListV1ResponseMPayloadAllOf
 */
export class ValidationObjectUsergroupGetListV1ResponseMPayloadAllOf {
   a_objUsergroup = {
      type: 'array',
      required: true
   }
} 


