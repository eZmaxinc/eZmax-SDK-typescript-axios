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
import { UsergroupResponseCompound } from './usergroup-response-compound';

/**
 * Response for GET /1/object/usergroupexternal/{pkiUsergroupexternalID}/getUsergroups
 * @export
 * @interface UsergroupexternalGetUsergroupsV1ResponseMPayload
 */
export interface UsergroupexternalGetUsergroupsV1ResponseMPayload {
    /**
     * 
     * @type {Array<UsergroupResponseCompound>}
     * @memberof UsergroupexternalGetUsergroupsV1ResponseMPayload
     */
    'a_objUsergroup': Array<UsergroupResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupexternalGetUsergroupsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalGetUsergroupsV1ResponseMPayload
 */
export class DataObjectUsergroupexternalGetUsergroupsV1ResponseMPayload {
   a_objUsergroup:Array<UsergroupResponseCompound> = []
}

/**
 * @export 
 * A UsergroupexternalGetUsergroupsV1ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupexternalGetUsergroupsV1ResponseMPayload
 */
export class ValidationObjectUsergroupexternalGetUsergroupsV1ResponseMPayload {
   a_objUsergroup = {
      type: 'array',
      required: true
   }
} 


