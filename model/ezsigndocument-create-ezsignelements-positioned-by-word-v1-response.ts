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
import type { EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload } from './ezsigndocument-create-ezsignelements-positioned-by-word-v1-response-mpayload';

/**
 * @type EzsigndocumentCreateEzsignelementsPositionedByWordV1Response
 * Response for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/createEzsignelementsPositionedByWord
 * @export
 */
/*export type EzsigndocumentCreateEzsignelementsPositionedByWordV1Response = CommonResponse;*/
export interface EzsigndocumentCreateEzsignelementsPositionedByWordV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndocumentCreateEzsignelementsPositionedByWordV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndocumentCreateEzsignelementsPositionedByWordV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload}
     * @memberof EzsigndocumentCreateEzsignelementsPositionedByWordV1Response
     */
    mPayload:EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload 
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
import { DataObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentCreateEzsignelementsPositionedByWordV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1Response
 */
export class DataObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload = new DataObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentCreateEzsignelementsPositionedByWordV1Response Validation Object
 * @class ValidationObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1Response
 */
export class ValidationObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigndocumentCreateEzsignelementsPositionedByWordV1ResponseMPayload()
} 


