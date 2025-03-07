/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
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
import type { EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload } from './ezsigntemplatedocument-edit-ezsigntemplateformfieldgroups-v1-response-mpayload';

/**
 * @type EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response
 * Response for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplateformfieldgroups
 * @export
 */
/*export type EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response = CommonResponse;*/
export interface EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response
     */
    mPayload:EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload 
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
import { DataObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response
 */
export class DataObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload = new DataObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response
 */
export class ValidationObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload()
} 


