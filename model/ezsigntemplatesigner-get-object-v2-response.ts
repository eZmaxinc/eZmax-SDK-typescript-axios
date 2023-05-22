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
import { EzsigntemplatesignerGetObjectV2ResponseAllOf } from './ezsigntemplatesigner-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignerGetObjectV2ResponseMPayload } from './ezsigntemplatesigner-get-object-v2-response-mpayload';

/**
 * @type EzsigntemplatesignerGetObjectV2Response
 * Response for GET /2/object/ezsigntemplatesigner/{pkiEzsigntemplatesignerID}
 * @export
 */
export type EzsigntemplatesignerGetObjectV2Response = CommonResponse & EzsigntemplatesignerGetObjectV2ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatesignerGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatesignerGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigntemplatesignerGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignerGetObjectV2Response
 */
export class DataObjectEzsigntemplatesignerGetObjectV2Response {
   mPayload:EzsigntemplatesignerGetObjectV2ResponseMPayload = new DataObjectEzsigntemplatesignerGetObjectV2ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayload = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigntemplatesignerGetObjectV2Response Validation Object
 * @class ValidationObjectEzsigntemplatesignerGetObjectV2Response
 */
export class ValidationObjectEzsigntemplatesignerGetObjectV2Response {
   mPayload = new ValidationObjectEzsigntemplatesignerGetObjectV2ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


