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
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateGetListV1ResponseAllOf } from './ezsigntemplate-get-list-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateGetListV1ResponseMPayload } from './ezsigntemplate-get-list-v1-response-mpayload';

/**
 * @type EzsigntemplateGetListV1Response
 * Response for GET /1/object/ezsigntemplate/getList
 * @export
 */
export type EzsigntemplateGetListV1Response = CommonResponseGetList & EzsigntemplateGetListV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateGetListV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigntemplateGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateGetListV1Response
 */
export class DataObjectEzsigntemplateGetListV1Response {
    mPayload:EzsigntemplateGetListV1ResponseMPayload = new DataObjectEzsigntemplateGetListV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayloadGetList = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigntemplateGetListV1Response Validation Object
 * @class ValidationObjectEzsigntemplateGetListV1Response
 */
export class ValidationObjectEzsigntemplateGetListV1Response {
   mPayload = new ValidationObjectEzsigntemplateGetListV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


