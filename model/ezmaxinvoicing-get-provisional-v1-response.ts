/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
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
import { EzmaxinvoicingGetProvisionalV1ResponseMPayload } from './ezmaxinvoicing-get-provisional-v1-response-mpayload';

/**
 * @type EzmaxinvoicingGetProvisionalV1Response
 * Response for GET /1/object/ezmaxinvoicing/getProvisional
 * @export
 */
/** export type EzmaxinvoicingGetProvisionalV1Response = CommonResponse; */
export interface EzmaxinvoicingGetProvisionalV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzmaxinvoicingGetProvisionalV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzmaxinvoicingGetProvisionalV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzmaxinvoicingGetProvisionalV1ResponseMPayload}
     * @memberof EzmaxinvoicingGetProvisionalV1Response
     */
    mPayload:EzmaxinvoicingGetProvisionalV1ResponseMPayload 
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
import { DataObjectEzmaxinvoicingGetProvisionalV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzmaxinvoicingGetProvisionalV1ResponseMPayload } from './'

/**
 * @export 
 * A EzmaxinvoicingGetProvisionalV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingGetProvisionalV1Response
 */
export class DataObjectEzmaxinvoicingGetProvisionalV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzmaxinvoicingGetProvisionalV1ResponseMPayload = new DataObjectEzmaxinvoicingGetProvisionalV1ResponseMPayload()
}

/**
 * @export 
 * A EzmaxinvoicingGetProvisionalV1Response Validation Object
 * @class ValidationObjectEzmaxinvoicingGetProvisionalV1Response
 */
export class ValidationObjectEzmaxinvoicingGetProvisionalV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzmaxinvoicingGetProvisionalV1ResponseMPayload()
} 


