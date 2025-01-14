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
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { DomainGetListV1ResponseMPayload } from './domain-get-list-v1-response-mpayload';

/**
 * @type DomainGetListV1Response
 * Response for GET /1/object/domain/getList
 * @export
 */
/*export type DomainGetListV1Response = CommonResponseGetList;*/
export interface DomainGetListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof DomainGetListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof DomainGetListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {DomainGetListV1ResponseMPayload}
     * @memberof DomainGetListV1Response
     */
    mPayload:DomainGetListV1ResponseMPayload 
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
import { DataObjectDomainGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectDomainGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A DomainGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDomainGetListV1Response
 */
export class DataObjectDomainGetListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:DomainGetListV1ResponseMPayload = new DataObjectDomainGetListV1ResponseMPayload()
}

/**
 * @export 
 * A DomainGetListV1Response Validation Object
 * @class ValidationObjectDomainGetListV1Response
 */
export class ValidationObjectDomainGetListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectDomainGetListV1ResponseMPayload()
} 


