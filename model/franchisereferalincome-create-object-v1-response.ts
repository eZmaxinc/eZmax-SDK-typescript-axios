/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.48
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponse } from './common-response';
import { CommonResponseObjDebug } from './common-response-obj-debug';
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
import { FranchisereferalincomeCreateObjectV1ResponseAllOf } from './franchisereferalincome-create-object-v1-response-all-of';
import { FranchisereferalincomeCreateObjectV1ResponseMPayload } from './franchisereferalincome-create-object-v1-response-mpayload';



/**
 * Response for the /1/object/franchisereferalincome/createObject API Request
 * @export
 * @interface FranchisereferalincomeCreateObjectV1Response
 */
export interface FranchisereferalincomeCreateObjectV1Response {
    /**
     * 
     * @type {FranchisereferalincomeCreateObjectV1ResponseMPayload}
     * @memberof FranchisereferalincomeCreateObjectV1Response
     */
    mPayload: FranchisereferalincomeCreateObjectV1ResponseMPayload;
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof FranchisereferalincomeCreateObjectV1Response
     */
    objDebugPayload?: CommonResponseObjDebugPayload;
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof FranchisereferalincomeCreateObjectV1Response
     */
    objDebug?: CommonResponseObjDebug;
}
