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
import { UsergroupexternalResponseCompound } from './usergroupexternal-response-compound';

/**
 * Response for GET /1/object/user/{pkiUserID}/getUsergroupexternals
 * @export
 * @interface UserGetUsergroupexternalsV1ResponseMPayload
 */
export interface UserGetUsergroupexternalsV1ResponseMPayload {
    /**
     * 
     * @type {Array<UsergroupexternalResponseCompound>}
     * @memberof UserGetUsergroupexternalsV1ResponseMPayload
     */
    /*'a_objUsergroupexternal': Array<UsergroupexternalResponseCompound>;*/
    'a_objUsergroupexternal': Array<UsergroupexternalResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserGetUsergroupexternalsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetUsergroupexternalsV1ResponseMPayload
 */
export class DataObjectUserGetUsergroupexternalsV1ResponseMPayload {
   a_objUsergroupexternal:Array<UsergroupexternalResponseCompound> = []
}

/**
 * @export 
 * A UserGetUsergroupexternalsV1ResponseMPayload Validation Object
 * @class ValidationObjectUserGetUsergroupexternalsV1ResponseMPayload
 */
export class ValidationObjectUserGetUsergroupexternalsV1ResponseMPayload {
   a_objUsergroupexternal = {
      type: 'array',
      required: true
   }
} 

