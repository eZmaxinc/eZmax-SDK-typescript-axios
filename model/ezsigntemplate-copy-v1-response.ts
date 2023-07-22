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
import { EzsigntemplateCopyV1ResponseAllOf } from './ezsigntemplate-copy-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateCopyV1ResponseMPayload } from './ezsigntemplate-copy-v1-response-mpayload';

/**
 * @type EzsigntemplateCopyV1Response
 * Response for POST /1/object/ezsigntemplate/{pkiEzsigntemplateID}/copy
 * @export
 */
export type EzsigntemplateCopyV1Response = CommonResponse & EzsigntemplateCopyV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateCopyV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateCopyV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigntemplateCopyV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateCopyV1Response
 */
export class DataObjectEzsigntemplateCopyV1Response {
    mPayload:EzsigntemplateCopyV1ResponseMPayload = new DataObjectEzsigntemplateCopyV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigntemplateCopyV1Response Validation Object
 * @class ValidationObjectEzsigntemplateCopyV1Response
 */
export class ValidationObjectEzsigntemplateCopyV1Response {
   mPayload = new ValidationObjectEzsigntemplateCopyV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


