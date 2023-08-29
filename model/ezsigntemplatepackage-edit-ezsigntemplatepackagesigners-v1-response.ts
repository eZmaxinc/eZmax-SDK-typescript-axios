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
import { EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload } from './ezsigntemplatepackage-edit-ezsigntemplatepackagesigners-v1-response-mpayload';

/**
 * @type EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response
 * Response for PUT /1/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID}/editEzsigntemplatepackagesigners
 * @export
 */
export type EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response = CommonResponse;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response
 */
export class DataObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload = new DataObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response
 */
export class ValidationObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload()
} 


