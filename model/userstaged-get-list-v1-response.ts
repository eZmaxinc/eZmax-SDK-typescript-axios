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
import type { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { UserstagedGetListV1ResponseMPayload } from './userstaged-get-list-v1-response-mpayload';

/**
 * @type UserstagedGetListV1Response
 * Response for GET /1/object/userstaged/getList
 * @export
 */
/*export type UserstagedGetListV1Response = CommonResponseGetList;*/
export interface UserstagedGetListV1Response {
    /**
     * 
     * @type {UserstagedGetListV1ResponseMPayload}
     * @memberof UserstagedGetListV1Response
     */
    mPayload:UserstagedGetListV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserstagedGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUserstagedGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A UserstagedGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedGetListV1Response
 */
export class DataObjectUserstagedGetListV1Response {
    mPayload:UserstagedGetListV1ResponseMPayload = new DataObjectUserstagedGetListV1ResponseMPayload()
}

/**
 * @export 
 * A UserstagedGetListV1Response Validation Object
 * @class ValidationObjectUserstagedGetListV1Response
 */
export class ValidationObjectUserstagedGetListV1Response {
   mPayload = new ValidationObjectUserstagedGetListV1ResponseMPayload()
} 


