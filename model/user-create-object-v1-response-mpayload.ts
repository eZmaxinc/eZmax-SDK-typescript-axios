/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Payload for POST /1/object/user
 * @export
 * @interface UserCreateObjectV1ResponseMPayload
 */
export interface UserCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof UserCreateObjectV1ResponseMPayload
     */
    /*'a_pkiUserID': Array<number>;*/
    'a_pkiUserID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserCreateObjectV1ResponseMPayload
 */
export class DataObjectUserCreateObjectV1ResponseMPayload {
   a_pkiUserID:Array<number> = []
}

/**
 * @export 
 * A UserCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectUserCreateObjectV1ResponseMPayload
 */
export class ValidationObjectUserCreateObjectV1ResponseMPayload {
   a_pkiUserID = {
      type: 'array',
      required: true
   }
} 


