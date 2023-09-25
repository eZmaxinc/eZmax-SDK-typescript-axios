/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageGetListV1ResponseMPayload } from './ezsigntemplatepackage-get-list-v1-response-mpayload';

/**
 * @type EzsigntemplatepackageGetListV1Response
 * Response for GET /1/object/ezsigntemplatepackage/getList
 * @export
 */
/** export type EzsigntemplatepackageGetListV1Response = CommonResponseGetList; */
export interface EzsigntemplatepackageGetListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof EzsigntemplatepackageGetListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepackageGetListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatepackageGetListV1ResponseMPayload}
     * @memberof EzsigntemplatepackageGetListV1Response
     */
    mPayload:EzsigntemplatepackageGetListV1ResponseMPayload 
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
import { DataObjectEzsigntemplatepackageGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackageGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackageGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageGetListV1Response
 */
export class DataObjectEzsigntemplatepackageGetListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepackageGetListV1ResponseMPayload = new DataObjectEzsigntemplatepackageGetListV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackageGetListV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepackageGetListV1Response
 */
export class ValidationObjectEzsigntemplatepackageGetListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepackageGetListV1ResponseMPayload()
} 


