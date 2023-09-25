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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload } from './ezsigntemplateformfieldgroup-create-object-v1-response-mpayload';

/**
 * @type EzsigntemplateformfieldgroupCreateObjectV1Response
 * Response for POST /1/object/ezsigntemplateformfieldgroup
 * @export
 */
/** export type EzsigntemplateformfieldgroupCreateObjectV1Response = CommonResponse; */
export interface EzsigntemplateformfieldgroupCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplateformfieldgroupCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplateformfieldgroupCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplateformfieldgroupCreateObjectV1Response
     */
    mPayload:EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplateformfieldgroupCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldgroupCreateObjectV1Response
 */
export class DataObjectEzsigntemplateformfieldgroupCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload = new DataObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplateformfieldgroupCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1Response
 */
export class ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload()
} 


