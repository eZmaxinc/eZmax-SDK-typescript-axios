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
import { EzsigntemplateGetObjectV1ResponseAllOf } from './ezsigntemplate-get-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateGetObjectV1ResponseMPayload } from './ezsigntemplate-get-object-v1-response-mpayload';

/**
 * @type EzsigntemplateGetObjectV1Response
 * Response for GET /1/object/ezsigntemplate/{pkiEzsigntemplateID}
 * @export
 */
export type EzsigntemplateGetObjectV1Response = CommonResponse & EzsigntemplateGetObjectV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateGetObjectV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateGetObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigntemplateGetObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateGetObjectV1Response
 */
export class DataObjectEzsigntemplateGetObjectV1Response {
    mPayload:EzsigntemplateGetObjectV1ResponseMPayload = new DataObjectEzsigntemplateGetObjectV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigntemplateGetObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplateGetObjectV1Response
 */
export class ValidationObjectEzsigntemplateGetObjectV1Response {
   mPayload = new ValidationObjectEzsigntemplateGetObjectV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


