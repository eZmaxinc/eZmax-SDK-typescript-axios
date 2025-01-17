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
import type { UsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload } from './usergroupexternal-get-usergroupexternalmemberships-v1-response-mpayload';

/**
 * @type UsergroupexternalGetUsergroupexternalmembershipsV1Response
 * Response for GET /1/object/usergroupexternal/{pkiUsergroupexternalID}/getUsergroupexternalmemberships
 * @export
 */
/*export type UsergroupexternalGetUsergroupexternalmembershipsV1Response = CommonResponse;*/
export interface UsergroupexternalGetUsergroupexternalmembershipsV1Response {
    /**
     * 
     * @type {UsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload}
     * @memberof UsergroupexternalGetUsergroupexternalmembershipsV1Response
     */
    mPayload:UsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupexternalGetUsergroupexternalmembershipsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalGetUsergroupexternalmembershipsV1Response
 */
export class DataObjectUsergroupexternalGetUsergroupexternalmembershipsV1Response {
    mPayload:UsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload = new DataObjectUsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupexternalGetUsergroupexternalmembershipsV1Response Validation Object
 * @class ValidationObjectUsergroupexternalGetUsergroupexternalmembershipsV1Response
 */
export class ValidationObjectUsergroupexternalGetUsergroupexternalmembershipsV1Response {
   mPayload = new ValidationObjectUsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload()
} 


