/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { EzsigndocumentGetActionableElementsV1ResponseAllOf } from './ezsigndocument-get-actionable-elements-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetActionableElementsV1ResponseMPayload } from './ezsigndocument-get-actionable-elements-v1-response-mpayload';

/**
 * @type EzsigndocumentGetActionableElementsV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}/getActionableElements
 * @export
 */
export type EzsigndocumentGetActionableElementsV1Response = CommonResponse & EzsigndocumentGetActionableElementsV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentGetActionableElementsV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetActionableElementsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigndocumentGetActionableElementsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetActionableElementsV1Response
 */
export class DataObjectEzsigndocumentGetActionableElementsV1Response {
   mPayload:EzsigndocumentGetActionableElementsV1ResponseMPayload = new DataObjectEzsigndocumentGetActionableElementsV1ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayload = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigndocumentGetActionableElementsV1Response Validation Object
 * @class ValidationObjectEzsigndocumentGetActionableElementsV1Response
 */
export class ValidationObjectEzsigndocumentGetActionableElementsV1Response {
   mPayload = new ValidationObjectEzsigndocumentGetActionableElementsV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


