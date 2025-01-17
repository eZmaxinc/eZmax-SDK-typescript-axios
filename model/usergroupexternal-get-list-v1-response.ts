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
import type { UsergroupexternalGetListV1ResponseMPayload } from './usergroupexternal-get-list-v1-response-mpayload';

/**
 * @type UsergroupexternalGetListV1Response
 * Response for GET /1/object/usergroupexternal/getList
 * @export
 */
/*export type UsergroupexternalGetListV1Response = CommonResponseGetList;*/
export interface UsergroupexternalGetListV1Response {
    /**
     * 
     * @type {UsergroupexternalGetListV1ResponseMPayload}
     * @memberof UsergroupexternalGetListV1Response
     */
    mPayload:UsergroupexternalGetListV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupexternalGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUsergroupexternalGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupexternalGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalGetListV1Response
 */
export class DataObjectUsergroupexternalGetListV1Response {
    mPayload:UsergroupexternalGetListV1ResponseMPayload = new DataObjectUsergroupexternalGetListV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupexternalGetListV1Response Validation Object
 * @class ValidationObjectUsergroupexternalGetListV1Response
 */
export class ValidationObjectUsergroupexternalGetListV1Response {
   mPayload = new ValidationObjectUsergroupexternalGetListV1ResponseMPayload()
} 


