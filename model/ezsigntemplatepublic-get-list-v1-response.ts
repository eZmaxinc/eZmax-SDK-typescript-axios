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
import type { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepublicGetListV1ResponseMPayload } from './ezsigntemplatepublic-get-list-v1-response-mpayload';

/**
 * @type EzsigntemplatepublicGetListV1Response
 * Response for GET /1/object/ezsigntemplatepublic/getList
 * @export
 */
/*export type EzsigntemplatepublicGetListV1Response = CommonResponseGetList;*/
export interface EzsigntemplatepublicGetListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof EzsigntemplatepublicGetListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepublicGetListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatepublicGetListV1ResponseMPayload}
     * @memberof EzsigntemplatepublicGetListV1Response
     */
    mPayload:EzsigntemplatepublicGetListV1ResponseMPayload 
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
import { DataObjectEzsigntemplatepublicGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepublicGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepublicGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicGetListV1Response
 */
export class DataObjectEzsigntemplatepublicGetListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepublicGetListV1ResponseMPayload = new DataObjectEzsigntemplatepublicGetListV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepublicGetListV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepublicGetListV1Response
 */
export class ValidationObjectEzsigntemplatepublicGetListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepublicGetListV1ResponseMPayload()
} 


