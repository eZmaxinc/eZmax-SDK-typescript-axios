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
import { EzsigndocumentCreateObjectV2ResponseAllOf } from './ezsigndocument-create-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentCreateObjectV2ResponseMPayload } from './ezsigndocument-create-object-v2-response-mpayload';

/**
 * @type EzsigndocumentCreateObjectV2Response
 * Response for POST /2/object/ezsigndocument
 * @export
 */
export type EzsigndocumentCreateObjectV2Response = CommonResponse & EzsigndocumentCreateObjectV2ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigndocumentCreateObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentCreateObjectV2Response
 */
export class DataObjectEzsigndocumentCreateObjectV2Response {
   mPayload:EzsigndocumentCreateObjectV2ResponseMPayload = new DataObjectEzsigndocumentCreateObjectV2ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayload = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigndocumentCreateObjectV2Response Validation Object
 * @class ValidationObjectEzsigndocumentCreateObjectV2Response
 */
export class ValidationObjectEzsigndocumentCreateObjectV2Response {
   mPayload = new ValidationObjectEzsigndocumentCreateObjectV2ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


