/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
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
import { EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseAllOf } from './ezsigntemplatedocument-get-ezsigntemplatedocumentpages-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload } from './ezsigntemplatedocument-get-ezsigntemplatedocumentpages-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response
 * Response for GET /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getEzsigntemplatedocumentpages
 * @export
 */
export type EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response = CommonResponse & EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseAllOf;


/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response
 */
export class DefaultObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response extends DefaultObject {
   mPayload:Partial<EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


