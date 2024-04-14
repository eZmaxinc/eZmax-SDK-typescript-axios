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



/**
 * Payload for POST /1/object/userstaged/{pkiUserstagedID}/createUser
 * @export
 * @interface UserstagedCreateUserV1ResponseMPayload
 */
export interface UserstagedCreateUserV1ResponseMPayload {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UserstagedCreateUserV1ResponseMPayload
     */
    /*'pkiUserID': number;*/
    'pkiUserID': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserstagedCreateUserV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedCreateUserV1ResponseMPayload
 */
export class DataObjectUserstagedCreateUserV1ResponseMPayload {
   pkiUserID:number = 0
}

/**
 * @export 
 * A UserstagedCreateUserV1ResponseMPayload Validation Object
 * @class ValidationObjectUserstagedCreateUserV1ResponseMPayload
 */
export class ValidationObjectUserstagedCreateUserV1ResponseMPayload {
   pkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
} 


