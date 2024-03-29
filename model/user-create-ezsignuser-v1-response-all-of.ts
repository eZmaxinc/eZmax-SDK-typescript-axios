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
import { UserCreateEzsignuserV1ResponseMPayload } from './user-create-ezsignuser-v1-response-mpayload';

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
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserCreateEzsignuserV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUserCreateEzsignuserV1ResponseMPayload } from './'

/**
 * @export 
 * A UserCreateEzsignuserV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserCreateEzsignuserV1ResponseAllOf
 */
export class DataObjectUserCreateEzsignuserV1ResponseAllOf {
   mPayload:UserCreateEzsignuserV1ResponseMPayload = new DataObjectUserCreateEzsignuserV1ResponseMPayload()
}

/**
 * @export 
 * A UserCreateEzsignuserV1ResponseAllOf Validation Object
 * @class ValidationObjectUserCreateEzsignuserV1ResponseAllOf
 */
export class ValidationObjectUserCreateEzsignuserV1ResponseAllOf {
   mPayload = new ValidationObjectUserCreateEzsignuserV1ResponseMPayload()
} 


