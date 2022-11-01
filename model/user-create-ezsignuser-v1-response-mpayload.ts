/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Payload for POST /1/module/user/createEzsignuser
 * @export
 * @interface UserCreateEzsignuserV1ResponseMPayload
 */
export interface UserCreateEzsignuserV1ResponseMPayload {
    /**
     * An array of email addresses that succeeded.
     * @type {Array<string>}
     * @memberof UserCreateEzsignuserV1ResponseMPayload
     */
    'a_sEmailAddressSuccess': Array<string>;
    /**
     * An array of email addresses that failed.
     * @type {Array<string>}
     * @memberof UserCreateEzsignuserV1ResponseMPayload
     */
    'a_sEmailAddressFailure': Array<string>;
}
/**
 * A UserCreateEzsignuserV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectUserCreateEzsignuserV1ResponseMPayload
 */
export class DefaultObjectUserCreateEzsignuserV1ResponseMPayload extends DefaultObject {
   a_sEmailAddressSuccess:Array<string> = []
   a_sEmailAddressFailure:Array<string> = []
}


