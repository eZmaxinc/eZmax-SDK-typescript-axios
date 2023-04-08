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
import { EzsigndocumentGetObjectV2ResponseAllOf } from './ezsigndocument-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetObjectV2ResponseMPayload } from './ezsigndocument-get-object-v2-response-mpayload';

/**
 * @type EzsigndocumentGetObjectV2Response
 * Response for GET /2/object/ezsigndocument/{pkiEzsigndocumentID}
 * @export
 */
export type EzsigndocumentGetObjectV2Response = CommonResponse & EzsigndocumentGetObjectV2ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigndocumentGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetObjectV2Response
 */
export class DataObjectEzsigndocumentGetObjectV2Response {
   mPayload:EzsigndocumentGetObjectV2ResponseMPayload = new DataObjectEzsigndocumentGetObjectV2ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayload = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigndocumentGetObjectV2Response Validation Object
 * @class ValidationObjectEzsigndocumentGetObjectV2Response
 */
export class ValidationObjectEzsigndocumentGetObjectV2Response {
   mPayload = new ValidationObjectEzsigndocumentGetObjectV2ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


