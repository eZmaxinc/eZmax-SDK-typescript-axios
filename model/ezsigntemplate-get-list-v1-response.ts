/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
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

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplateGetListV1Response
 * Response for GET /1/object/ezsigntemplate/getList
 * @export
 */
export type EzsigntemplateGetListV1Response = CommonResponseGetList & EzsigntemplateGetListV1ResponseAllOf;


/**
 * @export 
 * A EzsigntemplateGetListV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplateGetListV1Response
 */
export class DefaultObjectEzsigntemplateGetListV1Response extends DefaultObject {
   mPayload:Partial<EzsigntemplateGetListV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayloadGetList> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


