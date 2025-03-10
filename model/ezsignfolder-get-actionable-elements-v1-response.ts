/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfolderGetActionableElementsV1ResponseMPayload } from './ezsignfolder-get-actionable-elements-v1-response-mpayload';

/**
 * @type EzsignfolderGetActionableElementsV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getActionableElements
 * @export
 */
/*export type EzsignfolderGetActionableElementsV1Response = CommonResponse;*/
export interface EzsignfolderGetActionableElementsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfolderGetActionableElementsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfolderGetActionableElementsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignfolderGetActionableElementsV1ResponseMPayload}
     * @memberof EzsignfolderGetActionableElementsV1Response
     */
    mPayload:EzsignfolderGetActionableElementsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzsignfolderGetActionableElementsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetActionableElementsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetActionableElementsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetActionableElementsV1Response
 */
export class DataObjectEzsignfolderGetActionableElementsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignfolderGetActionableElementsV1ResponseMPayload = new DataObjectEzsignfolderGetActionableElementsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetActionableElementsV1Response Validation Object
 * @class ValidationObjectEzsignfolderGetActionableElementsV1Response
 */
export class ValidationObjectEzsignfolderGetActionableElementsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignfolderGetActionableElementsV1ResponseMPayload()
} 


