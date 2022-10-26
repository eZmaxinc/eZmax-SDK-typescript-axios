/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
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
import { EzsignbulksendGetFormsDataV1ResponseAllOf } from './ezsignbulksend-get-forms-data-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendGetFormsDataV1ResponseMPayload } from './ezsignbulksend-get-forms-data-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignbulksendGetFormsDataV1Response
 * Response for GET /1/object/ezsignbulksend/{pkiEzsignbulksendID}/getFormsData
 * @export
 */
export type EzsignbulksendGetFormsDataV1Response = CommonResponse & EzsignbulksendGetFormsDataV1ResponseAllOf;


/**
 * @export 
 * A EzsignbulksendGetFormsDataV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksendGetFormsDataV1Response
 */
export class DefaultObjectEzsignbulksendGetFormsDataV1Response extends DefaultObject {
   mPayload:Partial<EzsignbulksendGetFormsDataV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


