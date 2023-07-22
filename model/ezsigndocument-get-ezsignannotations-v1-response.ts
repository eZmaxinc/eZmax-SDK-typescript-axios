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
import { EzsigndocumentGetEzsignannotationsV1ResponseAllOf } from './ezsigndocument-get-ezsignannotations-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetEzsignannotationsV1ResponseMPayload } from './ezsigndocument-get-ezsignannotations-v1-response-mpayload';

/**
 * @type EzsigndocumentGetEzsignannotationsV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsignannotations
 * @export
 */
export type EzsigndocumentGetEzsignannotationsV1Response = CommonResponse & EzsigndocumentGetEzsignannotationsV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentGetEzsignannotationsV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetEzsignannotationsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigndocumentGetEzsignannotationsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetEzsignannotationsV1Response
 */
export class DataObjectEzsigndocumentGetEzsignannotationsV1Response {
    mPayload:EzsigndocumentGetEzsignannotationsV1ResponseMPayload = new DataObjectEzsigndocumentGetEzsignannotationsV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigndocumentGetEzsignannotationsV1Response Validation Object
 * @class ValidationObjectEzsigndocumentGetEzsignannotationsV1Response
 */
export class ValidationObjectEzsigndocumentGetEzsignannotationsV1Response {
   mPayload = new ValidationObjectEzsigndocumentGetEzsignannotationsV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


