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
import { EzsignsignatureGetObjectV2ResponseAllOf } from './ezsignsignature-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureGetObjectV2ResponseMPayload } from './ezsignsignature-get-object-v2-response-mpayload';

/**
 * @type EzsignsignatureGetObjectV2Response
 * Response for GET /2/object/ezsignsignature/{pkiEzsignsignatureID}
 * @export
 */
export type EzsignsignatureGetObjectV2Response = CommonResponse & EzsignsignatureGetObjectV2ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignatureGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignsignatureGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureGetObjectV2Response
 */
export class DataObjectEzsignsignatureGetObjectV2Response {
   mPayload:EzsignsignatureGetObjectV2ResponseMPayload = new DataObjectEzsignsignatureGetObjectV2ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayload = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignsignatureGetObjectV2Response Validation Object
 * @class ValidationObjectEzsignsignatureGetObjectV2Response
 */
export class ValidationObjectEzsignsignatureGetObjectV2Response {
   mPayload = new ValidationObjectEzsignsignatureGetObjectV2ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


