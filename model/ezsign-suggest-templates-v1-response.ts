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
import { EzsignSuggestTemplatesV1ResponseAllOf } from './ezsign-suggest-templates-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignSuggestTemplatesV1ResponseMPayload } from './ezsign-suggest-templates-v1-response-mpayload';

/**
 * @type EzsignSuggestTemplatesV1Response
 * Response for GET /1/module/ezsign/suggestTemplates
 * @export
 */
export type EzsignSuggestTemplatesV1Response = CommonResponse & EzsignSuggestTemplatesV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignSuggestTemplatesV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignSuggestTemplatesV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignSuggestTemplatesV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignSuggestTemplatesV1Response
 */
export class DataObjectEzsignSuggestTemplatesV1Response {
    mPayload:EzsignSuggestTemplatesV1ResponseMPayload = new DataObjectEzsignSuggestTemplatesV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignSuggestTemplatesV1Response Validation Object
 * @class ValidationObjectEzsignSuggestTemplatesV1Response
 */
export class ValidationObjectEzsignSuggestTemplatesV1Response {
   mPayload = new ValidationObjectEzsignSuggestTemplatesV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


