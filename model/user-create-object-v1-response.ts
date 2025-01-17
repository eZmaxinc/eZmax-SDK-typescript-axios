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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { UserCreateObjectV1ResponseMPayload } from './user-create-object-v1-response-mpayload';

/**
 * @type UserCreateObjectV1Response
 * Response for POST /1/object/user
 * @export
 */
/*export type UserCreateObjectV1Response = CommonResponse;*/
export interface UserCreateObjectV1Response {
    /**
     * 
     * @type {UserCreateObjectV1ResponseMPayload}
     * @memberof UserCreateObjectV1Response
     */
    mPayload:UserCreateObjectV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUserCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A UserCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserCreateObjectV1Response
 */
export class DataObjectUserCreateObjectV1Response {
    mPayload:UserCreateObjectV1ResponseMPayload = new DataObjectUserCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A UserCreateObjectV1Response Validation Object
 * @class ValidationObjectUserCreateObjectV1Response
 */
export class ValidationObjectUserCreateObjectV1Response {
   mPayload = new ValidationObjectUserCreateObjectV1ResponseMPayload()
} 


