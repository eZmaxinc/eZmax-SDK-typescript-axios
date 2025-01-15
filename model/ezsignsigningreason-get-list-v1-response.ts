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
import type { EzsignsigningreasonGetListV1ResponseMPayload } from './ezsignsigningreason-get-list-v1-response-mpayload';

/**
 * @type EzsignsigningreasonGetListV1Response
 * Response for GET /1/object/ezsignsigningreason/getList
 * @export
 */
/*export type EzsignsigningreasonGetListV1Response = CommonResponseGetList;*/
export interface EzsignsigningreasonGetListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof EzsignsigningreasonGetListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignsigningreasonGetListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignsigningreasonGetListV1ResponseMPayload}
     * @memberof EzsignsigningreasonGetListV1Response
     */
    mPayload:EzsignsigningreasonGetListV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzsignsigningreasonGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsigningreasonGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsigningreasonGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsigningreasonGetListV1Response
 */
export class DataObjectEzsignsigningreasonGetListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignsigningreasonGetListV1ResponseMPayload = new DataObjectEzsignsigningreasonGetListV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignsigningreasonGetListV1Response Validation Object
 * @class ValidationObjectEzsignsigningreasonGetListV1Response
 */
export class ValidationObjectEzsignsigningreasonGetListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignsigningreasonGetListV1ResponseMPayload()
} 


