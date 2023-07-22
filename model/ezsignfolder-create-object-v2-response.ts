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
import { EzsignfolderCreateObjectV2ResponseAllOf } from './ezsignfolder-create-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderCreateObjectV2ResponseMPayload } from './ezsignfolder-create-object-v2-response-mpayload';

/**
 * @type EzsignfolderCreateObjectV2Response
 * Response for POST /2/object/ezsignfolder
 * @export
 */
export type EzsignfolderCreateObjectV2Response = CommonResponse & EzsignfolderCreateObjectV2ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignfolderCreateObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderCreateObjectV2Response
 */
export class DataObjectEzsignfolderCreateObjectV2Response {
    mPayload:EzsignfolderCreateObjectV2ResponseMPayload = new DataObjectEzsignfolderCreateObjectV2ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignfolderCreateObjectV2Response Validation Object
 * @class ValidationObjectEzsignfolderCreateObjectV2Response
 */
export class ValidationObjectEzsignfolderCreateObjectV2Response {
   mPayload = new ValidationObjectEzsignfolderCreateObjectV2ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


