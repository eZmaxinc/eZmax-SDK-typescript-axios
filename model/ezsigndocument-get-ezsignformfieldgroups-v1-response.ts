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
import { EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload } from './ezsigndocument-get-ezsignformfieldgroups-v1-response-mpayload';

/**
 * @type EzsigndocumentGetEzsignformfieldgroupsV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsignformfieldgroups
 * @export
 */
/*export type EzsigndocumentGetEzsignformfieldgroupsV1Response = CommonResponse;*/
export interface EzsigndocumentGetEzsignformfieldgroupsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndocumentGetEzsignformfieldgroupsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndocumentGetEzsignformfieldgroupsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload}
     * @memberof EzsigndocumentGetEzsignformfieldgroupsV1Response
     */
    mPayload:EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload 
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
import { DataObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentGetEzsignformfieldgroupsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetEzsignformfieldgroupsV1Response
 */
export class DataObjectEzsigndocumentGetEzsignformfieldgroupsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload = new DataObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentGetEzsignformfieldgroupsV1Response Validation Object
 * @class ValidationObjectEzsigndocumentGetEzsignformfieldgroupsV1Response
 */
export class ValidationObjectEzsigndocumentGetEzsignformfieldgroupsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload()
} 


