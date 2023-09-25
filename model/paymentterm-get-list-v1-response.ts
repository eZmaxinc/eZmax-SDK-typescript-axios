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
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { PaymenttermGetListV1ResponseMPayload } from './paymentterm-get-list-v1-response-mpayload';

/**
 * @type PaymenttermGetListV1Response
 * Response for GET /1/object/paymentterm/getList
 * @export
 */
/** export type PaymenttermGetListV1Response = CommonResponseGetList; */
export interface PaymenttermGetListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof PaymenttermGetListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof PaymenttermGetListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {PaymenttermGetListV1ResponseMPayload}
     * @memberof PaymenttermGetListV1Response
     */
    mPayload:PaymenttermGetListV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectPaymenttermGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectPaymenttermGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A PaymenttermGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermGetListV1Response
 */
export class DataObjectPaymenttermGetListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:PaymenttermGetListV1ResponseMPayload = new DataObjectPaymenttermGetListV1ResponseMPayload()
}

/**
 * @export 
 * A PaymenttermGetListV1Response Validation Object
 * @class ValidationObjectPaymenttermGetListV1Response
 */
export class ValidationObjectPaymenttermGetListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectPaymenttermGetListV1ResponseMPayload()
} 


