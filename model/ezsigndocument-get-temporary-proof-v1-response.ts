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
import { EzsigndocumentGetTemporaryProofV1ResponseAllOf } from './ezsigndocument-get-temporary-proof-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetTemporaryProofV1ResponseMPayload } from './ezsigndocument-get-temporary-proof-v1-response-mpayload';

/**
 * @type EzsigndocumentGetTemporaryProofV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}/getTemporaryProof
 * @export
 */
export type EzsigndocumentGetTemporaryProofV1Response = CommonResponse & EzsigndocumentGetTemporaryProofV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigndocumentGetTemporaryProofV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetTemporaryProofV1Response
 */
export class DataObjectEzsigndocumentGetTemporaryProofV1Response {
    mPayload:EzsigndocumentGetTemporaryProofV1ResponseMPayload = new DataObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigndocumentGetTemporaryProofV1Response Validation Object
 * @class ValidationObjectEzsigndocumentGetTemporaryProofV1Response
 */
export class ValidationObjectEzsigndocumentGetTemporaryProofV1Response {
   mPayload = new ValidationObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


