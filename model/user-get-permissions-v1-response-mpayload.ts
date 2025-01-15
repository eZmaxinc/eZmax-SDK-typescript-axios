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
import type { ModulegroupResponseCompound } from './modulegroup-response-compound';

/**
 * Response for GET /1/object/user/{pkiUserID}/getPermissions
 * @export
 * @interface UserGetPermissionsV1ResponseMPayload
 */
export interface UserGetPermissionsV1ResponseMPayload {
    /**
     * 
     * @type {Array<ModulegroupResponseCompound>}
     * @memberof UserGetPermissionsV1ResponseMPayload
     */
    /*'a_objModulegroup': Array<ModulegroupResponseCompound>;*/
    'a_objModulegroup': Array<ModulegroupResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserGetPermissionsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetPermissionsV1ResponseMPayload
 */
export class DataObjectUserGetPermissionsV1ResponseMPayload {
   a_objModulegroup:Array<ModulegroupResponseCompound> = []
}

/**
 * @export 
 * A UserGetPermissionsV1ResponseMPayload Validation Object
 * @class ValidationObjectUserGetPermissionsV1ResponseMPayload
 */
export class ValidationObjectUserGetPermissionsV1ResponseMPayload {
   a_objModulegroup = {
      type: 'array',
      required: true
   }
} 


