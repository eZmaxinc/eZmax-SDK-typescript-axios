/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
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
import { EzsigntemplatepublicGetFormsDataV1ResponseMPayload } from './ezsigntemplatepublic-get-forms-data-v1-response-mpayload';

/**
 * @type EzsigntemplatepublicGetFormsDataV1Response
 * Response for GET /1/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID}/getFormsData
 * @export
 */
/*export type EzsigntemplatepublicGetFormsDataV1Response = CommonResponse;*/
export interface EzsigntemplatepublicGetFormsDataV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatepublicGetFormsDataV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepublicGetFormsDataV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatepublicGetFormsDataV1ResponseMPayload}
     * @memberof EzsigntemplatepublicGetFormsDataV1Response
     */
    mPayload:EzsigntemplatepublicGetFormsDataV1ResponseMPayload 
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
import { DataObjectEzsigntemplatepublicGetFormsDataV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepublicGetFormsDataV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepublicGetFormsDataV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicGetFormsDataV1Response
 */
export class DataObjectEzsigntemplatepublicGetFormsDataV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepublicGetFormsDataV1ResponseMPayload = new DataObjectEzsigntemplatepublicGetFormsDataV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepublicGetFormsDataV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepublicGetFormsDataV1Response
 */
export class ValidationObjectEzsigntemplatepublicGetFormsDataV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepublicGetFormsDataV1ResponseMPayload()
} 


