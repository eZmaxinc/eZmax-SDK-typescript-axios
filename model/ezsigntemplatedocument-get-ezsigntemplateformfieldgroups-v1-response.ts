/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
import { EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf } from './ezsigntemplatedocument-get-ezsigntemplateformfieldgroups-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload } from './ezsigntemplatedocument-get-ezsigntemplateformfieldgroups-v1-response-mpayload';

/**
 * @type EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response
 * Response for GET /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocument}/getEzsigntemplateformfieldgroups
 * @export
 */
export type EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response = CommonResponse & EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response
 */
export class DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response {
    mPayload:EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload = new DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response Validation Object
 * @class ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response
 */
export class ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response {
   mPayload = new ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


