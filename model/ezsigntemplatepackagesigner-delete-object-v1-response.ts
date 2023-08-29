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
import { EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload } from './ezsigntemplatepackagesigner-delete-object-v1-response-mpayload';

/**
 * @type EzsigntemplatepackagesignerDeleteObjectV1Response
 * Response for DELETE /1/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID}
 * @export
 */
export type EzsigntemplatepackagesignerDeleteObjectV1Response = CommonResponse;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackagesignerDeleteObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignerDeleteObjectV1Response
 */
export class DataObjectEzsigntemplatepackagesignerDeleteObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload = new DataObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackagesignerDeleteObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignerDeleteObjectV1Response
 */
export class ValidationObjectEzsigntemplatepackagesignerDeleteObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload()
} 


