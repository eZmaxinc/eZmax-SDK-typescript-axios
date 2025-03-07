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
import type { CreditcardclientCreateObjectV1ResponseMPayload } from './creditcardclient-create-object-v1-response-mpayload';

/**
 * @type CreditcardclientCreateObjectV1Response
 * Response for POST /1/object/creditcardclient
 * @export
 */
/*export type CreditcardclientCreateObjectV1Response = CommonResponse;*/
export interface CreditcardclientCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof CreditcardclientCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof CreditcardclientCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {CreditcardclientCreateObjectV1ResponseMPayload}
     * @memberof CreditcardclientCreateObjectV1Response
     */
    mPayload:CreditcardclientCreateObjectV1ResponseMPayload 
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
import { DataObjectCreditcardclientCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectCreditcardclientCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A CreditcardclientCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardclientCreateObjectV1Response
 */
export class DataObjectCreditcardclientCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:CreditcardclientCreateObjectV1ResponseMPayload = new DataObjectCreditcardclientCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A CreditcardclientCreateObjectV1Response Validation Object
 * @class ValidationObjectCreditcardclientCreateObjectV1Response
 */
export class ValidationObjectCreditcardclientCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectCreditcardclientCreateObjectV1ResponseMPayload()
} 


