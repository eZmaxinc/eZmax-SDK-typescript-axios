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
import { PaymenttermGetObjectV2ResponseMPayload } from './paymentterm-get-object-v2-response-mpayload';

/**
 * @type PaymenttermGetObjectV2Response
 * Response for GET /2/object/paymentterm/{pkiPaymenttermID}
 * @export
 */
export type PaymenttermGetObjectV2Response = CommonResponse;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectPaymenttermGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectPaymenttermGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A PaymenttermGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermGetObjectV2Response
 */
export class DataObjectPaymenttermGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:PaymenttermGetObjectV2ResponseMPayload = new DataObjectPaymenttermGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A PaymenttermGetObjectV2Response Validation Object
 * @class ValidationObjectPaymenttermGetObjectV2Response
 */
export class ValidationObjectPaymenttermGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectPaymenttermGetObjectV2ResponseMPayload()
} 


