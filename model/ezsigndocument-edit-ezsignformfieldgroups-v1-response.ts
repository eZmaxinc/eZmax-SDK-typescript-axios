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
import { EzsigndocumentEditEzsignformfieldgroupsV1ResponseAllOf } from './ezsigndocument-edit-ezsignformfieldgroups-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload } from './ezsigndocument-edit-ezsignformfieldgroups-v1-response-mpayload';

/**
 * @type EzsigndocumentEditEzsignformfieldgroupsV1Response
 * Response for PUT /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignformfieldgroups
 * @export
 */
export type EzsigndocumentEditEzsignformfieldgroupsV1Response = CommonResponse & EzsigndocumentEditEzsignformfieldgroupsV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigndocumentEditEzsignformfieldgroupsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentEditEzsignformfieldgroupsV1Response
 */
export class DataObjectEzsigndocumentEditEzsignformfieldgroupsV1Response {
    mPayload:EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload = new DataObjectEzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigndocumentEditEzsignformfieldgroupsV1Response Validation Object
 * @class ValidationObjectEzsigndocumentEditEzsignformfieldgroupsV1Response
 */
export class ValidationObjectEzsigndocumentEditEzsignformfieldgroupsV1Response {
   mPayload = new ValidationObjectEzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


