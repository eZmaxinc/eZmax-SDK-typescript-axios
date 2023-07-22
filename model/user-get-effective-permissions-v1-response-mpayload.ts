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
import { ModulegroupResponseCompound } from './modulegroup-response-compound';

/**
 * Response for GET /1/object/user/{pkiUserID}/getEffectivePermissions
 * @export
 * @interface UserGetEffectivePermissionsV1ResponseMPayload
 */
export interface UserGetEffectivePermissionsV1ResponseMPayload {
    /**
     * 
     * @type {Array<ModulegroupResponseCompound>}
     * @memberof UserGetEffectivePermissionsV1ResponseMPayload
     */
    'a_objModulegroup': Array<ModulegroupResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserGetEffectivePermissionsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetEffectivePermissionsV1ResponseMPayload
 */
export class DataObjectUserGetEffectivePermissionsV1ResponseMPayload {
   a_objModulegroup:Array<ModulegroupResponseCompound> = []
}

/**
 * @export 
 * A UserGetEffectivePermissionsV1ResponseMPayload Validation Object
 * @class ValidationObjectUserGetEffectivePermissionsV1ResponseMPayload
 */
export class ValidationObjectUserGetEffectivePermissionsV1ResponseMPayload {
   a_objModulegroup = {
      type: 'array',
      required: true
   }
} 


