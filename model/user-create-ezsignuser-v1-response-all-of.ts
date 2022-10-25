/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { UserCreateEzsignuserV1ResponseMPayload } from './user-create-ezsignuser-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface UserCreateEzsignuserV1ResponseAllOf
 */
export interface UserCreateEzsignuserV1ResponseAllOf {
    /**
     * 
     * @type {UserCreateEzsignuserV1ResponseMPayload}
     * @memberof UserCreateEzsignuserV1ResponseAllOf
     */
    'mPayload': UserCreateEzsignuserV1ResponseMPayload;
}
/**
 * A UserCreateEzsignuserV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectUserCreateEzsignuserV1ResponseAllOf
 */
export class DefaultObjectUserCreateEzsignuserV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<UserCreateEzsignuserV1ResponseMPayload> = {}
}


