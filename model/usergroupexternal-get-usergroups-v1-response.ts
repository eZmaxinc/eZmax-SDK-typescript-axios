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
import type { UsergroupexternalGetUsergroupsV1ResponseMPayload } from './usergroupexternal-get-usergroups-v1-response-mpayload';

/**
 * @type UsergroupexternalGetUsergroupsV1Response
 * Response for GET /1/object/usergroupexternal/{pkiUsergroupexternalID}/getUsergroups
 * @export
 */
/*export type UsergroupexternalGetUsergroupsV1Response = CommonResponse;*/
export interface UsergroupexternalGetUsergroupsV1Response {
    /**
     * 
     * @type {UsergroupexternalGetUsergroupsV1ResponseMPayload}
     * @memberof UsergroupexternalGetUsergroupsV1Response
     */
    mPayload:UsergroupexternalGetUsergroupsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupexternalGetUsergroupsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUsergroupexternalGetUsergroupsV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupexternalGetUsergroupsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalGetUsergroupsV1Response
 */
export class DataObjectUsergroupexternalGetUsergroupsV1Response {
    mPayload:UsergroupexternalGetUsergroupsV1ResponseMPayload = new DataObjectUsergroupexternalGetUsergroupsV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupexternalGetUsergroupsV1Response Validation Object
 * @class ValidationObjectUsergroupexternalGetUsergroupsV1Response
 */
export class ValidationObjectUsergroupexternalGetUsergroupsV1Response {
   mPayload = new ValidationObjectUsergroupexternalGetUsergroupsV1ResponseMPayload()
} 


