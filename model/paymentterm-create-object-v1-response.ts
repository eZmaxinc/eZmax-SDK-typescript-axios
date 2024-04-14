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
import { PaymenttermCreateObjectV1ResponseMPayload } from './paymentterm-create-object-v1-response-mpayload';

/**
 * @type PaymenttermCreateObjectV1Response
 * Response for POST /1/object/paymentterm
 * @export
 */
/*export type PaymenttermCreateObjectV1Response = CommonResponse;*/
export interface PaymenttermCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof PaymenttermCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof PaymenttermCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {PaymenttermCreateObjectV1ResponseMPayload}
     * @memberof PaymenttermCreateObjectV1Response
     */
    mPayload:PaymenttermCreateObjectV1ResponseMPayload 
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
import { DataObjectPaymenttermCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectPaymenttermCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A PaymenttermCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermCreateObjectV1Response
 */
export class DataObjectPaymenttermCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:PaymenttermCreateObjectV1ResponseMPayload = new DataObjectPaymenttermCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A PaymenttermCreateObjectV1Response Validation Object
 * @class ValidationObjectPaymenttermCreateObjectV1Response
 */
export class ValidationObjectPaymenttermCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectPaymenttermCreateObjectV1ResponseMPayload()
} 


